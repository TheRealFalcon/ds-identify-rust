use std::str::FromStr;
use std::{
    fs::File,
    path::{Path, PathBuf},
};

use serde_yaml::Value;

use crate::Paths;

/// Merge two `serde_yaml::Value` objects. If the two values are both mappings,
/// merge the values in the second mapping into the first. If the two values are
/// not mappings, the second value overwrites the first.
fn merge_values(base: Value, overwrite: &Value) -> Value {
    match (base, overwrite) {
        (Value::Mapping(mut base_map), Value::Mapping(overwrite_map)) => {
            for (key, value) in overwrite_map.iter() {
                let key = key.clone();
                if let Some(base_value) = base_map.get_mut(&key) {
                    let merged_value = merge_values(base_value.clone(), value);
                    *base_value = merged_value;
                } else {
                    base_map.insert(key, value.clone());
                }
            }
            Value::Mapping(base_map)
        }
        _ => overwrite.clone(),
    }
}

/// List the paths of all the cloud.cfg files in /etc/cloud/cloud.cfg.d in order
/// of precedence. This includes putting /etc/cloud/cloud.cfg at the beginning
fn get_all_cloud_cfg_paths(paths: &Paths) -> Vec<PathBuf> {
    let dir_contents = Path::new(&paths.etc_ci_cfg_d)
        .read_dir()
        .expect("Unable to read directory");
    let mut all_cfg_files: Vec<PathBuf> = Vec::new();
    for dir_result in dir_contents {
        let dir_entry = dir_result.unwrap();
        let filename_os_str = dir_entry.file_name();
        let filename = filename_os_str.to_str().unwrap();
        if filename.ends_with(".cfg") {
            all_cfg_files.push(dir_entry.path());
        }
    }
    all_cfg_files.sort();
    all_cfg_files.insert(0, PathBuf::from_str(&paths.etc_ci_cfg).unwrap());
    all_cfg_files
}

/// Read the cloud.cfg file and all the files in /etc/cloud/cloud.cfg.d merged in
pub fn read_cloud_cfg_with_conf_d(paths: &Paths) -> Value {
    let cloud_cfgs = get_all_cloud_cfg_paths(paths);
    let mut combined_config: Value = Value::Null;
    for cfg_path in cloud_cfgs {
        let cfg_yaml: Value = serde_yaml::from_reader(File::open(cfg_path).unwrap()).unwrap();
        combined_config = merge_values(combined_config, &cfg_yaml);
    }
    combined_config
}
