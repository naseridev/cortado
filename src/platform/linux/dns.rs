use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::logging::Logger;
use crate::platform::DnsConfigurator;

pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
pub const RESOLV_CONF_BACKUP_PATH: &str = "/etc/resolv.conf.cortado.bak";

pub struct ResolvConf {
    path: PathBuf,
    backup_path: PathBuf,
    current: Option<IpAddr>,
    original: Option<Vec<u8>>,
}

impl ResolvConf {
    pub fn new(path: impl Into<PathBuf>, backup_path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            backup_path: backup_path.into(),
            current: None,
            original: None,
        }
    }

    pub fn system() -> Self {
        Self::new(RESOLV_CONF_PATH, RESOLV_CONF_BACKUP_PATH)
    }

    fn write_nameserver(&self, server: IpAddr) -> Result<()> {
        fs::write(&self.path, format!("nameserver {}\n", server))
            .context("failed to write resolv.conf")
    }

    fn ensure_backup(&mut self) -> Result<()> {
        if self.original.is_none() {
            let original = fs::read(&self.path).ok();
            if let Some(ref orig) = original {
                fs::write(&self.backup_path, orig).context("failed to backup resolv.conf")?;
            }
            self.original = original;
        }
        Ok(())
    }

    pub fn current(&self) -> Option<IpAddr> {
        self.current
    }
}

impl DnsConfigurator for ResolvConf {
    fn apply(&mut self, server: Option<IpAddr>, log: &Logger) -> Result<()> {
        let dns = match server {
            Some(dns) => dns,
            None => return Ok(()),
        };
        self.ensure_backup()?;
        self.write_nameserver(dns)?;
        self.current = Some(dns);
        log.info(format!("DNS redirected to {}", dns));
        Ok(())
    }

    fn reload(&mut self, server: Option<IpAddr>, log: &Logger) -> Result<()> {
        if server == self.current {
            return Ok(());
        }
        match server {
            Some(dns) => {
                self.ensure_backup()?;
                self.write_nameserver(dns)?;
                log.info(format!("DNS redirected to {} (reload)", dns));
            }
            None => {
                if let Some(orig) = &self.original {
                    fs::write(&self.path, orig).context("failed to restore resolv.conf")?;
                    let _ = fs::remove_file(&self.backup_path);
                    log.info("DNS override disabled (reload)");
                }
            }
        }
        self.current = server;
        Ok(())
    }

    fn restore(&mut self, log: &Logger) {
        if self.current.is_none() {
            return;
        }
        match &self.original {
            Some(orig) => {
                if let Err(e) = fs::write(&self.path, orig) {
                    log.warn(format!("failed to restore resolv.conf: {e}"));
                } else {
                    let _ = fs::remove_file(&self.backup_path);
                    log.info("resolv.conf restored");
                }
            }
            None => {
                if Path::new(&self.path).exists() {
                    log.warn("no resolv.conf backup, leaving as-is");
                }
            }
        }
        self.current = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::Logger;

    fn logger() -> Logger {
        Logger::new(false).0
    }

    fn temp_paths(tag: &str) -> (PathBuf, PathBuf) {
        let mut base = std::env::temp_dir();
        base.push(format!("cortado-resolv-{}-{}", std::process::id(), tag));
        let backup = base.with_extension("bak");
        (base, backup)
    }

    #[test]
    fn apply_writes_nameserver_and_backs_up() {
        let (path, backup) = temp_paths("apply");
        fs::write(&path, b"nameserver 192.168.1.1\n").unwrap();
        let mut rc = ResolvConf::new(&path, &backup);
        rc.apply(Some("1.1.1.1".parse().unwrap()), &logger())
            .unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(written, "nameserver 1.1.1.1\n");
        let backed = fs::read_to_string(&backup).unwrap();
        assert_eq!(backed, "nameserver 192.168.1.1\n");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&backup);
    }

    #[test]
    fn restore_returns_original() {
        let (path, backup) = temp_paths("restore");
        fs::write(&path, b"nameserver 8.8.8.8\n").unwrap();
        let mut rc = ResolvConf::new(&path, &backup);
        rc.apply(Some("1.1.1.1".parse().unwrap()), &logger())
            .unwrap();
        rc.restore(&logger());
        let restored = fs::read_to_string(&path).unwrap();
        assert_eq!(restored, "nameserver 8.8.8.8\n");
        assert!(!Path::new(&backup).exists());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reload_switches_nameserver() {
        let (path, backup) = temp_paths("reload");
        fs::write(&path, b"nameserver 8.8.8.8\n").unwrap();
        let mut rc = ResolvConf::new(&path, &backup);
        rc.apply(Some("1.1.1.1".parse().unwrap()), &logger())
            .unwrap();
        rc.reload(Some("9.9.9.9".parse().unwrap()), &logger())
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 9.9.9.9\n");
        assert_eq!(rc.current(), Some("9.9.9.9".parse().unwrap()));

        rc.reload(None, &logger()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 8.8.8.8\n");
        assert_eq!(rc.current(), None);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&backup);
    }

    #[test]
    fn apply_none_is_noop() {
        let (path, backup) = temp_paths("none");
        let mut rc = ResolvConf::new(&path, &backup);
        rc.apply(None, &logger()).unwrap();
        assert!(!Path::new(&path).exists());
        assert_eq!(rc.current(), None);
    }
}
