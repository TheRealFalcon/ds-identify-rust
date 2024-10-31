// TODO: REMOVE THESE ONCE EVERYTHING DOESNT SUCK
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

mod cloud_cfg_parser;

use log::{debug, LevelFilter};

use core::str;
use std::{
    collections::HashMap,
    env, fmt,
    fs::{self, File},
    os::unix::prelude::FileTypeExt,
    path::Path,
    process::Command,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_with::DeserializeFromStr;
use serde_yaml::Value;
use smbioslib::{
    table_load_from_device, SMBiosInformation, SMBiosSystemChassisInformation,
    SMBiosSystemInformation,
};

use crate::cloud_cfg_parser::read_cloud_cfg_with_conf_d;

#[derive(Serialize, Debug)]
enum Sources {
    Maas,
    ConfigDrive,
    NoCloud,
    AltCloud,
    Azure,
    Bigstep,
    CloudSigma,
    CloudStack,
    DigitalOcean,
    Vultr,
    AliYun,
    Ec2,
    Gce,
    OpenNebula,
    OpenStack,
    Ovf,
    SmartOS,
    Scaleway,
    Hetzner,
    IBMCloud,
    Oracle,
    Exoscale,
    RbxCloud,
    UpCloud,
    VMware,
    Lxd,
    Nwcs,
}

impl fmt::Display for Sources {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Sources::Maas => write!(f, "MAAS"),
            Sources::ConfigDrive => write!(f, "ConfigDrive"),
            Sources::NoCloud => write!(f, "NoCloud"),
            Sources::AltCloud => write!(f, "AltCloud"),
            Sources::Azure => write!(f, "Azure"),
            Sources::Bigstep => write!(f, "Bigstep"),
            Sources::CloudSigma => write!(f, "CloudSigma"),
            Sources::CloudStack => write!(f, "CloudStack"),
            Sources::DigitalOcean => write!(f, "DigitalOcean"),
            Sources::Vultr => write!(f, "Vultr"),
            Sources::AliYun => write!(f, "AliYun"),
            Sources::Ec2 => write!(f, "Ec2"),
            Sources::Gce => write!(f, "GCE"),
            Sources::OpenNebula => write!(f, "OpenNebula"),
            Sources::OpenStack => write!(f, "OpenStack"),
            Sources::Ovf => write!(f, "OVF"),
            Sources::SmartOS => write!(f, "SmartOS"),
            Sources::Scaleway => write!(f, "Scaleway"),
            Sources::Hetzner => write!(f, "Hetzner"),
            Sources::IBMCloud => write!(f, "IBMCloud"),
            Sources::Oracle => write!(f, "Oracle"),
            Sources::Exoscale => write!(f, "Exoscale"),
            Sources::RbxCloud => write!(f, "RbxCloud"),
            Sources::UpCloud => write!(f, "UpCloud"),
            Sources::VMware => write!(f, "VMware"),
            Sources::Lxd => write!(f, "LXD"),
            Sources::Nwcs => write!(f, "NWCS"),
        }
    }
}

const ORDERED_SOURCES: [Sources; 27] = [
    Sources::Maas,
    Sources::ConfigDrive,
    Sources::NoCloud,
    Sources::AltCloud,
    Sources::Azure,
    Sources::Bigstep,
    Sources::CloudSigma,
    Sources::CloudStack,
    Sources::DigitalOcean,
    Sources::Vultr,
    Sources::AliYun,
    Sources::Ec2,
    Sources::Gce,
    Sources::OpenNebula,
    Sources::OpenStack,
    Sources::Ovf,
    Sources::SmartOS,
    Sources::Scaleway,
    Sources::Hetzner,
    Sources::IBMCloud,
    Sources::Oracle,
    Sources::Exoscale,
    Sources::RbxCloud,
    Sources::UpCloud,
    Sources::VMware,
    Sources::Lxd,
    Sources::Nwcs,
];

pub struct Paths {
    root: String,
    run: String,
    sys_class_dmi_id: String,
    sys_hypervisor: String,
    sys_class_block: String,
    dev_disk: String,
    var_lib_cloud: String,
    di_config: String,
    proc_cmdline: String,
    proc_1_cmdline: String,
    proc_1_environ: String,
    proc_uptime: String,
    etc_cloud: String,
    etc_ci_cfg: String,
    etc_ci_cfg_d: String,
    run_ci: String,
    run_ci_cfg: String,
    run_di_result: String,
}

fn get_paths() -> Paths {
    // WHY DID I RE-IMPLEMENT THIS?
    let root = env::var("PATH_ROOT").unwrap_or("".to_string());
    let run = env::var("PATH_RUN").unwrap_or(format!("{}{}", root, "/run"));
    let sys_class_dmi_id =
        env::var("PATH_SYS_CLASS_DMI_ID").unwrap_or(format!("{}{}", root, "/sys/class/dmi/id"));
    let sys_hypervisor =
        env::var("PATH_SYS_HYPERVISOR").unwrap_or(format!("{}{}", root, "/sys/hypervisor"));
    let sys_class_block =
        env::var("PATH_SYS_CLASS_BLOCK").unwrap_or(format!("{}{}", root, "/sys/class/block"));
    let dev_disk = env::var("PATH_DEV_DISK").unwrap_or(format!("{}{}", root, "/dev/disk"));
    let var_lib_cloud =
        env::var("PATH_VAR_LIB_CLOUD").unwrap_or(format!("{}{}", root, "/var/lib/cloud"));
    let di_config =
        env::var("PATH_DI_CONFIG").unwrap_or(format!("{}{}", root, "/etc/cloud/ds-identify.cfg"));
    let proc_cmdline =
        env::var("PATH_PROC_CMDLINE").unwrap_or(format!("{}{}", root, "/proc/cmdline"));
    let proc_1_cmdline =
        env::var("PATH_PROC_1_CMDLINE").unwrap_or(format!("{}{}", root, "/proc/1/cmdline"));
    let proc_1_environ =
        env::var("PATH_PROC_1_ENVIRON").unwrap_or(format!("{}{}", root, "/proc/1/environ"));
    let proc_uptime = env::var("PATH_PROC_UPTIME").unwrap_or(format!("{}{}", root, "/proc/uptime"));
    let etc_cloud = env::var("PATH_ETC_CLOUD").unwrap_or(format!("{}{}", root, "/etc/cloud"));
    let etc_ci_cfg =
        env::var("PATH_ETC_CI_CFG").unwrap_or(format!("{}{}", etc_cloud, "/cloud.cfg"));
    let etc_ci_cfg_d = env::var("PATH_ETC_CI_CFG_D").unwrap_or(format!("{}{}", etc_ci_cfg, ".d"));
    let run_ci = env::var("PATH_RUN_CI").unwrap_or(format!("{}{}", run, "/cloud-init"));
    let run_ci_cfg = env::var("PATH_RUN_CI_CFG").unwrap_or(format!("{}{}", run_ci, "/cloud.cfg"));
    let run_di_result =
        env::var("PATH_RUN_DI_RESULT").unwrap_or(format!("{}{}", run_ci, "/.ds-identify.result"));
    Paths {
        root,
        run,
        sys_class_dmi_id,
        sys_hypervisor,
        sys_class_block,
        dev_disk,
        var_lib_cloud,
        di_config,
        proc_cmdline,
        proc_1_cmdline,
        proc_1_environ,
        proc_uptime,
        etc_cloud,
        etc_ci_cfg,
        etc_ci_cfg_d,
        run_ci,
        run_ci_cfg,
        run_di_result,
    }
}

struct UnameInfo {
    kernel_name: String,
    node_name: String,
    kernel_release: String,
    kernel_version: String,
    machine: String,
    operating_system: String,
    cmd_output: String,
}

enum VirtualizationEnvironment {
    Kvm,
    Microsoft,
    Qemu,
    VmWare,
    Xen,
    Container,
    None,
    Unavailable,
    // Docker,
    // Lxc,
    // LxcLibvirt,
    // Jail,
    // OpenVz,
    // Podman,
    // Proot,
    // Pouch,
    // Rkt,
    // SystemdNspawn,
    // Wsl,
}

enum DsCheck {
    Found,
    NotFound,
    Maybe,
}

impl FromStr for VirtualizationEnvironment {
    type Err = ();

    fn from_str(input: &str) -> Result<VirtualizationEnvironment, Self::Err> {
        // If our input came from $SYSTEMD_VIRTUALIZATION, it will be in the form of
        // something like "container:lxd" or "vm:kvm". Othewise, we only get the part
        // after the colon.
        let mut splits = input.split(':');
        let category = splits.next().unwrap();
        let implementation = splits.next().unwrap_or(category);
        if category == "container" {
            return Ok(VirtualizationEnvironment::Container);
        }
        match implementation.to_lowercase().as_str() {
            "container-other" | "docker" | "jail" | "lxc" | "lxc-libvirt" | "podman" | "rkt"
            | "systemd-nspawn" => Ok(VirtualizationEnvironment::Container),
            "kvm" => Ok(VirtualizationEnvironment::Kvm),
            "microsoft" => Ok(VirtualizationEnvironment::Microsoft),
            "qemu" => Ok(VirtualizationEnvironment::Qemu),
            "vmware" => Ok(VirtualizationEnvironment::VmWare),
            "xen" => Ok(VirtualizationEnvironment::Xen),
            "none" => Ok(VirtualizationEnvironment::None),
            _ => Ok(VirtualizationEnvironment::Unavailable),
        }
    }
}

fn read_uname_info() -> UnameInfo {
    // TODO: A uname library exists. Is it better than this?

    // Run uname, and parse output.
    // uname is tricky to parse as it outputs always in a given order
    // independent of option order. kernel-version is known to have spaces.
    // 1   -s kernel-name
    // 2   -n nodename
    // 3   -r kernel-release
    // 4.. -v kernel-version(whitespace)
    // N-2 -m machine
    // N-1 -o operating-system
    let result = Command::new("uname")
        .arg("-snrvmo")
        .output()
        .expect("Failed running uname");
    let cmd_output = str::from_utf8(&result.stdout)
        .expect("Failed obtaining uname output")
        .to_string();
    let mut split = cmd_output.split_ascii_whitespace();

    let parse_error = "Failed parsing uname output";

    let operating_system = split.next_back().expect(parse_error).to_string();
    let machine = split.next_back().expect(parse_error).to_string();
    let kernel_name = split.next().expect(parse_error).to_string();
    let node_name = split.next().expect(parse_error).to_string();
    let kernel_release = split.next().expect(parse_error).to_string();
    let kernel_version_vec: Vec<&str> = split.collect();
    let kernel_version = kernel_version_vec.join(" ");

    UnameInfo {
        kernel_name,
        node_name,
        kernel_release,
        kernel_version,
        machine,
        operating_system,
        cmd_output,
    }
}

fn detect_virt(uname_info: &UnameInfo) -> VirtualizationEnvironment {
    // Get DI_VIRT
    if Path::new("/run/systemd").is_dir() {
        let output = if let Ok(virt) = env::var("SYSTEMD_VIRTUALIZATION") {
            debug!("Using SYSTEMD_VIRTUALIZATION {}", virt);
            virt
        } else {
            // Get it from systemd-detect-virt
            let result = Command::new("systemd-detect-virt")
                .output()
                .expect("Failed running systemd-detect-virt");
            String::from_utf8(result.stdout).expect("Failed obtaining systemd-detect-virt output")
        };
        VirtualizationEnvironment::from_str(&output).unwrap()
    } else if uname_info.kernel_name == "FreeBSD" {
        let result = Command::new("sysctl")
            .args(["-qn", "kern.vm_guest"])
            .output()
            .expect("Failed running sysctl");
        if result.status.success() {
            let output = String::from_utf8(result.stdout).expect("Failed obtaining sysctl output");
            VirtualizationEnvironment::from_str(&output).unwrap()
        } else {
            let result = Command::new("sysctl")
                .args(["-qn", "security.jail.jailed"])
                .output()
                .expect("Failed running sysctl");
            let output = str::from_utf8(&result.stdout).expect("Failed obtaining sysctl output");
            VirtualizationEnvironment::from_str(output).unwrap()
        }
    } else {
        VirtualizationEnvironment::Unavailable
    }
}

fn read_kernel_cmdline(virt: &VirtualizationEnvironment, paths: &Paths) -> String {
    let proc_cmdline_path = Path::new(&paths.proc_cmdline);
    let proc_1_cmdline_path = Path::new(&paths.proc_1_cmdline);

    if matches!(virt, VirtualizationEnvironment::Container) {
        if proc_1_cmdline_path.is_file() {
            fs::read_to_string(proc_1_cmdline_path)
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to read kernel cmdline from {}",
                        paths.proc_1_cmdline
                    )
                })
                .replace('\0', " ")
        } else {
            "unavailable:container".to_string()
        }
    } else if proc_cmdline_path.is_file() {
        fs::read_to_string(proc_cmdline_path)
            .unwrap_or_else(|_| panic!("Failed to read kernel cmdline from {}", paths.proc_cmdline))
    } else {
        "unavailable:no-cmdline".to_string()
    }
}

fn has_seed_dir(name: &str, required_files: &[&str], var_lib_cloud_path: &str) -> bool {
    let seed_dir_str = &format!("{}/{}/{}", var_lib_cloud_path, "seed", name);
    let seed_dir = Path::new(seed_dir_str);
    if !seed_dir.is_dir() {
        return false;
    }
    for file in required_files {
        if !seed_dir.join(file).is_file() {
            return false;
        }
    }
    true
}

fn has_writable_seed_dir(name: &str, required_files: &[&str], paths: &Paths) -> bool {
    // ubuntu core bind-mounts /writable/system-data/var/lib/cloud
    // over the top of /var/lib/cloud, but the mount might not be done yet.
    let writable_path = format!("{}{}", &paths.root, "/writable/system-data");
    if !Path::is_dir(Path::new(&writable_path)) {
        return false;
    }
    let var_lib_cloud_no_root = paths.var_lib_cloud.replacen(&paths.root, "", 1);
    let var_lib_cloud_path = writable_path + &var_lib_cloud_no_root;
    has_seed_dir(name, required_files, &var_lib_cloud_path)
}

fn check_nocloud(
    kernel_cmdline: &str,
    dmi_product_serial: &str,
    paths: &Paths,
    fs_info: &FsInfo,
    cloud_cfg: &Value,
) -> DsCheck {
    // TODO: These checks are already outdated
    if kernel_cmdline.contains("ds=nocloud") {
        return DsCheck::Found;
    }
    if dmi_product_serial.contains("ds=nocloud") {
        return DsCheck::Found;
    }

    for dir in ["nocloud", "nocloud-net"] {
        if has_seed_dir(dir, &["meta-data", "user-data"], &paths.var_lib_cloud) {
            return DsCheck::Found;
        }
        if has_writable_seed_dir(dir, &["meta-data", "user-data"], paths) {
            return DsCheck::Found;
        }
    }

    if fs_info.labels.contains(&"cidata".to_string()) {
        println!("found NoCloud via label");
        return DsCheck::Found;
    }

    if !&cloud_cfg["datasource"]["NoCloud"]["user-data"].is_null()
        && !&cloud_cfg["datasource"]["NoCloud"]["meta-data"].is_null()
    {
        return DsCheck::Found;
    }

    DsCheck::NotFound
}

fn check_ec2(
    paths: &Paths,
    virtualization_environment: &VirtualizationEnvironment,
    dmi_product_serial: &str,
    dmi_chassis_asset_tag: &str,
    dmi_sys_vendor: &str,
    dmi_product_name: &str,
    dmi_uuid: &str,
    kernel_cmdline: &str,
    cloud_cfg: &Value,
    di_cfg: &DiCfg,
) -> DsCheck {
    // If seed dir exists, then found
    if has_seed_dir("ec2", &["meta-data", "user-data"], &paths.var_lib_cloud) {
        return DsCheck::Found;
    }
    // If we're in a container, not found
    if matches!(
        virtualization_environment,
        VirtualizationEnvironment::Container
    ) {
        return DsCheck::NotFound;
    }

    // Use DMI to identify EC2 as well as lookalikes that use the EC2 datasource
    if dmi_product_serial.ends_with(".brightbox.com") {
        return DsCheck::Found;
    }
    if dmi_chassis_asset_tag.ends_with(".zstack.io") {
        return DsCheck::Found;
    }
    if dmi_sys_vendor == "e24cloud" {
        return DsCheck::Found;
    }
    if dmi_product_name == "3DS Outscale VM" && dmi_sys_vendor == "3DS Outscale" {
        return DsCheck::Found;
    }
    let uuid = dmi_uuid.to_lowercase();
    let serial = dmi_product_serial.to_lowercase();
    if uuid.starts_with("ec2") && serial.starts_with("ec2") && uuid == serial {
        return DsCheck::Found;
    }

    // Xen uuid option
    let hypervisor_str = format!("{}/{}", paths.sys_hypervisor, "uuid");
    let hypervisor_path = Path::new(&hypervisor_str);
    if hypervisor_path.is_file()
        && fs::read_to_string(hypervisor_path)
            .unwrap()
            .starts_with("ec2")
    {
        return DsCheck::Found;
    }

    // Platform has not identified itself as ec2. By default this means "not found", but configuration
    // can be provided to override this as "maybe", so check for this configuration and apply
    // accordingly
    let cloud_cfg_strict = &cloud_cfg["datasource"]["Ec2"]["strict_id"];
    let strict_setting = if kernel_cmdline.contains("ci.datasource.ec2.strict_id=") {
        kernel_cmdline
            .split(' ')
            .find_map(|pair| {
                let mut parts = pair.split('-');
                let key = parts.next().unwrap();
                let value = parts.next().unwrap();
                if key == "ci.datasource.ec2.strict_id" {
                    Some(value)
                } else {
                    None
                }
            })
            .unwrap()
    } else if !cloud_cfg_strict.is_null() {
        cloud_cfg_strict.as_str().unwrap()
    } else if di_cfg.ec2_strict_id.is_some() {
        di_cfg.ec2_strict_id.as_ref().unwrap()
    } else {
        "true"
    };

    if strict_setting.to_lowercase() == "true" {
        DsCheck::NotFound
    } else {
        DsCheck::Maybe
    }
}

// This struct is a little weird, but it's taken from the original structures
// used by the bash version of ds-identify
struct FsInfo {
    labels: Vec<String>,
    uuids: Vec<String>,
    iso9660_devs: Vec<Iso9660Info>,
}

struct Iso9660Info {
    device: String,
    label: String,
}

fn read_fs_info() -> FsInfo {
    // We're working with data like
    // DEVNAME=/dev/vda
    // BLOCK_SIZE=2048
    // UUID=2023-06-23-20-23-55-00
    // LABEL=cidata
    // TYPE=iso9660

    let mut labels: Vec<String> = Vec::new();
    let mut uuids: Vec<String> = Vec::new();
    let mut iso9660_devs: Vec<Iso9660Info> = Vec::new();

    let blkid_cache = blkid::cache::Cache::new().expect("Failed getting blkid cache");
    blkid_cache.probe_all().expect("Failed blkid probe");
    let devs = blkid_cache.devs();
    for dev in devs {
        let tags = dev.tags();
        let mut label: String = "".to_string();
        let mut iso_dev: String = "".to_string();
        for tag in tags {
            let tag_name = tag.name();
            if tag_name.to_lowercase() == "label" {
                label = tag.value().to_string();
                labels.push(label.clone());
            } else if tag_name.to_lowercase() == "uuid" {
                uuids.push(tag.value().to_string());
            } else if tag_name.to_lowercase() == "type" && tag.value().to_lowercase() == "iso9660" {
                iso_dev = dev.name().to_string_lossy().to_string();
            }
        }
        if !label.is_empty() && !iso_dev.is_empty() {
            iso9660_devs.push(Iso9660Info {
                device: iso_dev,
                label,
            });
        }
    }
    FsInfo {
        labels,
        uuids,
        iso9660_devs,
    }
}

// fn ensure_bin_directories_on_path()
// Rust version of this should ensure bin directories in
// env passed to Command execution

fn maybe_create_run_cloud_init(paths: &Paths) {
    let run_ci_path = Path::new(&paths.run_ci);
    if !run_ci_path.is_dir() {
        fs::create_dir(run_ci_path).unwrap_or_else(|_| panic!("Failed creating {}", &paths.run_ci));
    }
}

#[derive(DeserializeFromStr, Debug)]
struct DiCfgPolicy {
    mode: String,
    found: String,
    maybe: String,
    notfound: String,
}

impl Default for DiCfgPolicy {
    fn default() -> Self {
        Self {
            mode: "search".to_string(),
            found: "all".to_string(),
            maybe: "none".to_string(),
            notfound: "disabled".to_string(),
        }
    }
}

impl FromStr for DiCfgPolicy {
    type Err = String;

    fn from_str(input: &str) -> Result<DiCfgPolicy, Self::Err> {
        let default = DiCfgPolicy::default();
        let mut tokens = input.split(',');
        let mode = tokens.next().map(|x| x.to_string()).unwrap_or(default.mode);
        let found = tokens
            .next()
            .and_then(|x| x.strip_prefix("found=").map(|s| s.to_string()))
            .unwrap_or(default.found);
        let maybe = tokens
            .next()
            .and_then(|x| x.strip_prefix("maybe=").map(|s| s.to_string()))
            .unwrap_or(default.maybe);
        let notfound = tokens
            .next()
            .and_then(|x| x.strip_prefix("notfound=").map(|s| s.to_string()))
            .unwrap_or(default.notfound);

        Ok(DiCfgPolicy {
            mode,
            found,
            maybe,
            notfound,
        })
    }
}

#[derive(Deserialize, Debug)]
struct DiCfg {
    datasource: Option<String>,
    policy: DiCfgPolicy,
    #[serde(rename = "ci.datasource.ec2.strict_id")]
    ec2_strict_id: Option<String>,
}

fn read_di_config(paths: &Paths) -> DiCfg {
    let di_config_path = Path::new(&paths.di_config);
    if !di_config_path.is_file() {
        return DiCfg {
            datasource: None,
            policy: DiCfgPolicy::default(),
            ec2_strict_id: None,
        };
    }

    serde_yaml::from_reader(File::open(di_config_path).unwrap()).unwrap()
}

fn floppy_available() -> bool {
    let devpath = "/dev/floppy";
    let is_block_device = fs::metadata(Path::new(devpath))
        .unwrap()
        .file_type()
        .is_block_device();
    let modprobe_result = Command::new("modprobe")
        .arg("--use-blacklist")
        .arg("floppy")
        .status()
        .unwrap()
        .success();
    let udevadm_settle_result = Command::new("udevadm")
        .arg("settle")
        .arg(format!("--exit-if-exists={}", devpath))
        .status()
        .unwrap()
        .success();
    is_block_device && modprobe_result && udevadm_settle_result
}

fn is_ibm_provisioning(paths: &Paths) -> bool {
    let provisioning_path = format!("{}{}", paths.root, "/root/provisioningConfiguration.cfg");
    let log_path = format!("{}{}", paths.root, "/root/swinstall.log");
    let provisioning_cfg = Path::new(&provisioning_path);
    let log = Path::new(&log_path);
    if provisioning_cfg.is_file() {
        if log.is_file() {
            log.metadata().unwrap().created().unwrap()
                > Path::new(&paths.proc_1_environ)
                    .metadata()
                    .unwrap()
                    .created()
                    .unwrap()
        } else {
            false
        }
    } else {
        true
    }
}

fn is_ibm_cloud(paths: &Paths, virt: &VirtualizationEnvironment, fs_info: &FsInfo) -> bool {
    let labels = &fs_info.labels;
    if matches!(virt, VirtualizationEnvironment::Xen) {
        is_ibm_provisioning(paths)
            || labels.contains(&"METADATA".to_string())
            || labels.contains(&"metadata".to_string())
            || fs_info.uuids.contains(&"9796-932E".to_string())
                && (labels.contains(&"CONFIG-2".to_string())
                    || labels.contains(&"config-2".to_string()))
    } else {
        false
    }
}

fn is_azure_chassis(dmi_asset_tag: &str) -> bool {
    dmi_asset_tag == "7783-7084-3265-9085-8269-3286-77"
}

fn has_ovf_vmware_transport_guestinfo(virt: &VirtualizationEnvironment) -> bool {
    if !matches!(virt, VirtualizationEnvironment::VmWare) {
        return false;
    }
    let rpctool_output = Command::new("vmware-rpctool")
        .arg("info-get")
        .arg("guestinfo.ovfEnv")
        .output();
    match rpctool_output {
        Ok(unparsed_output) => {
            match String::from_utf8(unparsed_output.stdout) {
                Ok(output) => {
                    if output.to_lowercase().starts_with("<?xml") {
                        // debug 1 "Found guestinfo transport."
                        true
                    } else {
                        // debug 1 "guestinfo.ovfEnv had non-xml content"
                        false
                    }
                }
                Err(_) => false, // unparseable binary content
            }
        }
        Err(_) => false, // failed to run or find vmware-rpctool
    }
}

fn has_ovf_cdrom(paths: &Paths, infos: &[Iso9660Info]) -> bool {
    let known_good_labels = ["ovf-transport", "ovfenv", "ovf env"];
    let known_bad_labels = ["config-2", "cidata"];
    for info in infos {
        let label = info.label.to_lowercase();

        if info.device.starts_with("/dev/sr") || info.device.starts_with("/dev/hd") {
            // debug 1 "skipping iso dev $dev"
            continue;
        }
        // debug 1 "got label=$label"

        if known_good_labels.contains(&label.as_str()) {
            return true;
        }
        if known_bad_labels.contains(&label.as_str()) || label.starts_with("rd_rdfe_stable") {
            continue;
        }

        // Original ds-identify has a 10MB limit that was checked here, but this isn't true anymore

        let full_path = format!("{}{}", paths.root, info.device);

        // TODO: do this in rust
        let schema_def = "http://schemas.dmtf.org/ovf/environment/1";
        let result = Command::new("grep")
            .arg("--ignore-case")
            .arg(schema_def)
            .arg(format!("{}{}", paths.root, info.device))
            .status();
        match result {
            Ok(status) => {
                if status.success() {
                    return true;
                } else {
                    continue;
                }
            }
            Err(e) => continue,
        }
    }
    false
}

struct SmBiosInfo {
    product_name: String,
    vendor: String,
    serial: String,
    asset_tag: String,
    product_uuid: String,
}

impl SmBiosInfo {
    fn from_dmi_tables() -> Self {
        // TODO: return option?
        let smbios_result = table_load_from_device();
        let (smbios_info, smbios_system_info, smbios_chassis_info) = match &smbios_result {
            Ok(data) => (
                data.first::<SMBiosInformation>()
                    .expect("Failed retrieving SMBios Information"),
                data.first::<SMBiosSystemInformation>()
                    .expect("Failed retrieving SMBios System information"),
                data.first::<SMBiosSystemChassisInformation>()
                    .expect("Failed retrieving SMBios Chassis information"),
            ),
            Err(err) => {
                return Self {
                    product_name: "".to_string(),
                    vendor: "".to_string(),
                    serial: "".to_string(),
                    asset_tag: "".to_string(),
                    product_uuid: "".to_string(),
                }
            }
        };

        let product_name = smbios_system_info.product_name().to_string();
        let vendor = smbios_info.vendor().to_string();
        let serial = smbios_system_info.serial_number().to_string();
        let asset_tag = smbios_chassis_info.asset_tag_number().to_string();

        let product_uuid = match smbios_system_info.uuid().unwrap() {
            smbioslib::SystemUuidData::Uuid(system_uuid) => {
                let uuid = system_uuid.raw;
                // bytes to string XD
                format!(
                "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6],
                uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13],
                uuid[14], uuid[15]
            )
            }
            _ => panic!(
                "TODO: Not sure why uuid is an option here. Might need to handle this for real."
            ),
        };

        Self {
            product_name,
            vendor,
            serial,
            asset_tag,
            product_uuid,
        }
    }
}

fn main() {
    let paths: Paths = get_paths();
    // Set up a simple logger
    let log_path = format!("{}/{}", &paths.run_ci, "rust-identify.log");
    simple_logging::log_to_file(log_path, LevelFilter::Debug).expect("Failed to setup logging");
    debug!("Start!");

    let uname_info: UnameInfo = read_uname_info();
    let virt: VirtualizationEnvironment = detect_virt(&uname_info);

    let kernel_cmdline: String = read_kernel_cmdline(&virt, &paths);
    let fs_info: FsInfo = read_fs_info();
    let cloud_cfg: Value = read_cloud_cfg_with_conf_d(&paths);

    maybe_create_run_cloud_init(&paths);
    let di_config = read_di_config(&paths);

    let smbios_info = SmBiosInfo::from_dmi_tables();

    let dmi_product_name = smbios_info.product_name;
    let dmi_vendor = smbios_info.vendor;
    let dmi_serial = smbios_info.serial;
    let dmi_product_uuid = smbios_info.product_uuid;
    let dmi_asset_tag = smbios_info.asset_tag;

    // Currently just stick with ds-identify defaults.
    // If Found, write all Found as datasource_list
    // If no Found, write all Maybe as datasource_list
    // If no Found and no Maybe, disable cloud-init
    let mut found: Vec<String> = Vec::new();
    let mut maybe: Vec<String> = Vec::new();
    for source in ORDERED_SOURCES {
        let result = match source {
            Sources::AliYun => {
                if dmi_product_name == "Alibaba Cloud ECS"
                    || has_seed_dir("AliYun", &["meta-data", "user-data"], &paths.var_lib_cloud)
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::AltCloud => {
                let path_str = format!("{}{}", &paths.root, "/etc/sysconfig/cloud-info");
                let path = Path::new(&path_str);
                let ctype = if path.is_file() {
                    fs::read_to_string(path).unwrap()
                } else {
                    dmi_product_name.clone()
                };
                match &ctype.to_lowercase()[..] {
                    "rhev" => {
                        if floppy_available() {
                            DsCheck::Maybe
                        } else {
                            DsCheck::NotFound
                        }
                    }
                    "vsphere" => {
                        let path = format!("{}/by-label/CDROM", &paths.dev_disk);
                        if fs::metadata(Path::new(&path))
                            .unwrap()
                            .file_type()
                            .is_block_device()
                        {
                            DsCheck::Maybe
                        } else {
                            DsCheck::NotFound
                        }
                    }
                    _ => DsCheck::NotFound,
                }
            }
            Sources::Azure => {
                if is_azure_chassis(&dmi_asset_tag)
                    || has_seed_dir("azure", &["meta-data", "user-data"], &paths.var_lib_cloud)
                    || matches!(virt, VirtualizationEnvironment::Microsoft)
                    || fs_info.labels.iter().any(|x| x.starts_with("rd_rdfe_"))
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::Bigstep => {
                let path = format!("{}{}", &paths.var_lib_cloud, "/data/seed/bigstep/url");
                if Path::new(&path).is_file() {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::CloudSigma => {
                if dmi_product_name == "CloudSigma" {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::CloudStack => {
                if dmi_product_name == "CloudStack" {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            // Sources::ConfigDrive => {
            //     let suffix = "/openstack/2???-??-??/meta_data.json";
            //     let vlc_config_drive_path =
            //         format!("{}{}", paths.var_lib_cloud, "/seed/config_drive");

            //     let json1 = &format!("{}{}", "/config_drive", suffix);
            //     let json2 = &format!("{}{}", vlc_config_drive_path, suffix);
            //     if glob(json1).unwrap().count() == 1 || glob(json2).unwrap().count() == 1 {
            //         DsCheck::Found
            //     } else if Path::new(&format!("{}{}", vlc_config_drive_path, "/openstack/latest/met_data.json")).is_file() {
            //         // debug 1 "config drive seeded directory had only 'latest'"
            //         DsCheck::Found
            //     } else if {
            //         // Pre-emptively ensure IBMCloud isn't recognized as config drive in next check

            //     }
            //     else {
            //         DsCheck::NotFound
            //     }
            //     TODO
            // }
            Sources::DigitalOcean => {
                if dmi_vendor == "DigitalOcean" {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::Ec2 => check_ec2(
                &paths,
                &virt,
                &dmi_serial,
                &dmi_asset_tag,
                &dmi_vendor,
                &dmi_product_name,
                &dmi_product_uuid,
                &kernel_cmdline,
                &cloud_cfg,
                &di_config,
            ),
            Sources::Exoscale => {
                if dmi_product_name == "Exoscale" {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::Gce => {
                if dmi_product_name == "Google Compute Engine"
                    || dmi_serial.starts_with("GoogleCloud")
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::Hetzner => {
                if dmi_vendor == "Hetzner" {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::IBMCloud => {
                if is_ibm_provisioning(&paths) {
                    //debug("cloud-init disabled during provisioning on IBMCloud");
                    DsCheck::NotFound
                } else if is_ibm_cloud(&paths, &virt, &fs_info) {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::Lxd => {
                let socket_str = format!("{}{}", &paths.root, "/dev/lxd/sock");
                let socket_path = Path::new(&socket_str);
                let board_str = format!("{}{}", &paths.root, "/sys/class/dmi/board_name");
                let board_path = Path::new(&board_str);

                if socket_path.exists()
                    && fs::metadata(socket_path).unwrap().file_type().is_socket()
                {
                    if socket_path.metadata().unwrap().file_type().is_socket()
                        || matches!(
                            virt,
                            VirtualizationEnvironment::Kvm | VirtualizationEnvironment::Qemu
                        ) && fs::read_to_string(board_path).unwrap() == "LXD"
                    {
                        DsCheck::Found
                    } else {
                        println!("shit1");
                        DsCheck::NotFound
                    }
                } else {
                    println!("shit");
                    DsCheck::NotFound
                }
            }
            Sources::Maas => {
                if (kernel_cmdline.contains("iqn.2004-05.com.ubuntu:maas")
                    && kernel_cmdline.contains("cloud-config-url="))
                    || !cloud_cfg["datasource"]["MAAS"].is_null()
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::NoCloud => {
                check_nocloud(&kernel_cmdline, &dmi_serial, &paths, &fs_info, &cloud_cfg)
            }
            Sources::Nwcs => {
                if dmi_vendor == "NWCS" {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::Ovf => {
                if has_seed_dir("ovf", &["meta-data", "user-data"], &paths.var_lib_cloud) {
                    DsCheck::Found
                } else if is_azure_chassis(&dmi_asset_tag) {
                    DsCheck::NotFound
                } else if has_ovf_vmware_transport_guestinfo(&virt)
                    || has_ovf_cdrom(&paths, &fs_info.iso9660_devs)
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::OpenNebula => {
                if has_seed_dir(
                    "opennebula",
                    &["meta-data", "user-data"],
                    &paths.var_lib_cloud,
                ) || fs_info.labels.contains(&"CONTEXT".to_string())
                    || fs_info.labels.contains(&"CDROM".to_string())
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            // Sources::OpenStack => DsCheck::TODO,
            Sources::Oracle => {
                if dmi_asset_tag == "OracleCloud.com" {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::RbxCloud => {
                if fs_info.labels.contains(&"CLOUDMD".to_string())
                    || fs_info.labels.contains(&"cloudmd".to_string())
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::Scaleway => {
                let path = format!("{}{}", &paths.root, "/var/run/scaleway");
                if dmi_vendor == "Scaleway"
                    || kernel_cmdline.contains(" scaleway ")
                    || Path::new(&path).is_file()
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::SmartOS => {
                let sockfile_path =
                    format!("{}{}", &paths.root, "/native/.zonecontrol/metadata.sock");
                let sockfile = Path::new(&sockfile_path);
                if dmi_product_name == "SmartDC"
                    || (uname_info.kernel_version == "BrandZ virtual linux" && sockfile.is_file())
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            Sources::UpCloud => {
                if dmi_vendor == "UpCloud" {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            // Sources::VMware => DsCheck::TODO,
            Sources::Vultr => {
                let path = format!("{}{}", &paths.root, "/etc/vultr");
                if dmi_vendor == "Vultr"
                    || kernel_cmdline.contains(" vultr ")
                    || Path::new(&path).is_file()
                {
                    DsCheck::Found
                } else {
                    DsCheck::NotFound
                }
            }
            _ => DsCheck::NotFound,
        };

        match result {
            DsCheck::Found => found.push(source.to_string()),
            DsCheck::Maybe => maybe.push(source.to_string()),
            DsCheck::NotFound => (),
        }
    }

    fs::create_dir_all(Path::new(&paths.run_ci_cfg).parent().unwrap())
        .expect("Failed creating cloud-init run dir");
    let cloud_cfg_file = File::create(&paths.run_ci_cfg).expect("Unable to create cloud.cfg");
    let datasource_list = if !found.is_empty() {
        found
    } else if !maybe.is_empty() {
        maybe
    } else {
        Vec::new()
    };

    let mut datasources = HashMap::new();
    datasources.insert("datasource_list".to_string(), datasource_list);
    serde_yaml::to_writer(&cloud_cfg_file, &datasources).expect("Failed writing to cloud.cfg");
    debug!("All done!");
}
