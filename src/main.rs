use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::{DNSClass, RData, Record, RecordType};
use trust_dns_proto::xfer::DnsRequestOptions;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::Name;
use trust_dns_resolver::AsyncResolver;
use trust_dns_server::authority::{Authority, Catalog};
use trust_dns_server::server::{Request, Response, ResponseBuilder, ServerFuture};
use trust_dns_server::proto::rr::RecordSet;
use futures::lock::Mutex;
use std::sync::Arc;

struct CacheEntry {
    valid_until: SystemTime,
    response: Vec<Record>,
}

struct ForwardingAuthority {
    resolver: AsyncResolver,
    cache: Arc<Mutex<HashMap<(Name, RecordType), CacheEntry>>>,
}

impl ForwardingAuthority {
    fn new() -> Self {
        let dns_servers = ["223.5.5.5", "223.6.6.6", "8.8.4.4"];
        let mut name_servers = NameServerConfigGroup::new();

        for dns_server in dns_servers.iter() {
            let ip: Ipv4Addr = dns_server.parse().expect("Unable to parse DNS server IP");
            let ns_config = NameServerConfigGroup::from_ips_clear(&[ip], 53);
            name_servers.extend(ns_config);
        }

        let (cfg, opts) = (ResolverConfig::from_parts(None, vec![], name_servers), ResolverOpts::default());
        let resolver = AsyncResolver::tokio(cfg, opts).unwrap();
        let cache = Arc::new(Mutex::new(HashMap::new()));

        Self { resolver, cache }
    }
}

#[async_trait::async_trait]
impl Authority for ForwardingAuthority {
    async fn lookup(
        &self,
        name: &Name,
        rrtype: RecordType,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> LookupResult {
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.get(&(name.clone(), rrtype)) {
            if entry.valid_until > SystemTime::now() {
                return Box::pin(RecordSet::from_records(name.clone(), entry.response.clone()).unwrap().into_iter());
            }
        }

        let response = self.resolver.lookup_ip(name.to_utf8().as_str()).await.unwrap();
        let mut records = Vec::new();
        for ip in response.iter() {
            let record = Record::from_rdata(
                name.clone(),
                3600,
                match ip {
                    IpAddr::V4(_) => RData::A(ip.into()),
                    IpAddr::V6(_) => RData::AAAA(ip.into()),
                },
            );
            records.push(record.clone());
        }

        cache.insert(
            (name.clone(), rrtype),
            CacheEntry {
                valid_until: SystemTime::now() + Duration::from_secs(3600),
                response: records.clone(),
            },
        );

        let record_set = RecordSet::from_records(name.clone(), records).unwrap();
        Box::pin(record_set.into_iter())
    }
}

#[tokio::main]
async fn main() {
    let authority = ForwardingAuthority::new();
    let mut catalog = Catalog::new();
    catalog.upsert(Name::from_str(".").unwrap(), Box::new(authority));

    let server = ServerFuture::new(catalog);

    server.listen_on("0.0.0.0:53").await.unwrap();
}
