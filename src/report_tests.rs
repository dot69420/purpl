#[cfg(test)]
mod tests {
    use crate::report::{parse_nmap_xml, parse_wifite_json, display_scan_report};
    use crate::io_handler::MockIoHandler;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_parse_nmap_xml() {
        let io = MockIoHandler::new();
        let xml = r#"
        <nmaprun>
            <host>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <address addr="00:11:22:33:44:55" addrtype="mac"/>
                <os>
                    <osmatch name="Linux 2.6"/>
                </os>
                <ports>
                    <port portid="22" protocol="tcp">
                        <service name="ssh" product="OpenSSH" version="7.6p1"/>
                    </port>
                    <port portid="80" protocol="tcp">
                        <service name="http"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        "#;

        let hosts = parse_nmap_xml(xml, &io);
        assert_eq!(hosts.len(), 1);
        let host = &hosts[0];
        assert_eq!(host.ip_v4, Some("192.168.1.1".to_string()));
        assert_eq!(host.mac, Some("00:11:22:33:44:55".to_string()));
        assert_eq!(host.os_name, Some("Linux 2.6".to_string()));
        assert_eq!(host.services.len(), 2);

        let ssh = &host.services[0];
        assert_eq!(ssh.port, "22");
        assert_eq!(ssh.name, "ssh");
        assert!(ssh.version.contains("OpenSSH"));

        let http = &host.services[1];
        assert_eq!(http.port, "80");
        assert_eq!(http.name, "http");
    }

    #[test]
    fn test_parse_wifite_json() {
        let io = MockIoHandler::new();
        let json = r#"
        [
            {
                "essid": "TestNetwork",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "key": "password123",
                "encryption": "WPA2"
            }
        ]
        "#;

        let entries = parse_wifite_json(json, &io);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].essid, "TestNetwork");
        assert_eq!(entries[0].bssid, "AA:BB:CC:DD:EE:FF");
        assert_eq!(entries[0].key, Some("password123".to_string()));
    }

    #[test]
    fn test_parse_wifite_json_empty() {
        let io = MockIoHandler::new();
        let json = "[]";
        let entries = parse_wifite_json(json, &io);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_wifite_json_invalid() {
        let io = MockIoHandler::new();
        let json = "invalid json";
        let entries = parse_wifite_json(json, &io);
        assert!(entries.is_empty());
        let out = io.get_output();
        assert!(out.contains("Could not parse"));
    }

    #[test]
    fn test_display_scan_report() {
        let io = MockIoHandler::new();
        // Setup dummy directory
        let scan_dir_name = format!("dummy_scan_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let scan_dir = Path::new(&scan_dir_name);
        fs::create_dir_all(scan_dir).unwrap();

        // 1. Create Nmap XML
        let xml = r#"<nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/><ports></ports></host></nmaprun>"#;
        fs::write(scan_dir.join("scan.xml"), xml).unwrap();

        // 2. Create Wifite JSON
        let json = r#"[{"essid":"test","bssid":"aa","key":"123","encryption":"WPA"}]"#;
        fs::write(scan_dir.join("cracked.json"), json).unwrap();

        // 3. Create Sniffer Report
        fs::write(scan_dir.join("report.txt"), "packets captured").unwrap();

        // 4. Create Bluetooth/Generic Scan
        fs::write(scan_dir.join("scan.txt"), "bluetooth devices found").unwrap();

        display_scan_report(scan_dir, &io);

        fs::remove_dir_all(scan_dir).unwrap();

        let out = io.get_output();
        assert!(out.contains("Parsing Nmap Report"));
        assert!(out.contains("Parsing Wifite Report"));
        assert!(out.contains("Reading Packet Sniffer Report"));
        assert!(out.contains("Reading Bluetooth/Generic Scan Report"));
    }
}
