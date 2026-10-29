//! Pemeriksaan terhadap basis data NVD nyata (hasil `sdrscan-vuln update --nvd`); dilewati bila tidak ada.
//! Jalankan: `SDRSCAN_REAL_DB=vulndb cargo test -p sdrscan-vulndb --test real_data -- --ignored --nocapture`

use std::collections::BTreeMap;

use sdrscan_vulndb::version::{Scheme, Version};
use sdrscan_vulndb::VulnDb;

#[test]
#[ignore = "butuh basis data nyata (env SDRSCAN_REAL_DB)"]
fn every_version_bound_in_real_nvd_data_is_parsable() {
    let Some(dir) = std::env::var_os("SDRSCAN_REAL_DB") else {
        return;
    };
    let db = VulnDb::open(std::path::Path::new(&dir)).unwrap();
    let mut bad: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total = 0usize;
    for e in db.read_nvd_entries().unwrap() {
        for m in &e.matches {
            for v in [
                &m.version,
                &m.start_including,
                &m.start_excluding,
                &m.end_including,
                &m.end_excluding,
            ]
            .into_iter()
            .flatten()
            {
                total += 1;
                if Version::parse(Scheme::Loose, v).is_none() {
                    bad.entry(e.product.clone())
                        .or_default()
                        .push(format!("{} {v}", e.id));
                }
            }
        }
    }
    println!(
        "total versi: {total}, tak terbaca: {}",
        bad.values().map(Vec::len).sum::<usize>()
    );
    for (p, v) in &bad {
        println!("{p}: {} contoh {:?}", v.len(), &v[..v.len().min(8)]);
    }
    assert!(
        bad.values().map(Vec::len).sum::<usize>() * 1000 < total,
        "terlalu banyak versi tak terbaca"
    );
}
