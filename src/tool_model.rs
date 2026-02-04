use serde::{Deserialize, Serialize};

// --- Execution Strategies (The "How") ---

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum SpecializedStrategy {
    // Complex, hardcoded logic (e.g. Nmap profiles, output parsing)
    Nmap,
    WebEnum,
    Fuzzer,
    ExploitActive,
    Poison,
    Wifi,
    Bluetooth,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum MenuCategory {
    Recon,
    Web,
    Exploit,
    NetOps,
    Wireless,
    UserTools,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolInput {
    Target,      // Asks for Target IP/URL
    Interface,   // Asks for Network Interface
    Wordlist,    // Asks for Wordlist Path
    Text(String), // Generic prompt (with label)
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolProfile {
    pub name: String,
    pub description: String,
    pub args_template: String,
}

// The "Standard" implementation (Data-driven)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpecification {
    pub binary: String,
    pub args_template: String,
    pub inputs: Vec<ToolInput>,
    pub profiles: Vec<ToolProfile>,
    pub requires_root: bool,
}

impl ToolSpecification {
    pub fn new(binary: &str, args_template: &str, inputs: Vec<ToolInput>) -> Self {
        Self {
            binary: binary.to_string(),
            args_template: args_template.to_string(),
            inputs,
            profiles: Vec::new(),
            requires_root: false,
        }
    }

    pub fn require_root(mut self) -> Self {
        self.requires_root = true;
        self
    }
}

#[derive(Clone, Debug)]
pub enum ToolImplementation {
    Specialized(SpecializedStrategy),
    Standard(ToolSpecification),
    Submenu(MenuCategory),
    PlaceholderAdd, // UI artifact
}

// --- Tool Identity (The "Who") ---

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ToolSource {
    System, // The Menu System itself
    Core,   // Main tools defined by the app (Value Proposal)
    User,   // Custom tools defined by the user
}

// The "Father" Entity
pub struct Tool {
    pub name: String,
    pub description: String,
    pub source: ToolSource,
    pub implementation: ToolImplementation,
}

impl Tool {
    // Create a top-level Category
    pub fn category(name: &str, cat: MenuCategory) -> Self {
        Self {
            name: name.to_string(),
            description: "Tool Category".to_string(),
            source: ToolSource::System,
            implementation: ToolImplementation::Submenu(cat),
        }
    }

    // Create a Core tool with specialized logic (e.g. Nmap)
    pub fn core_specialized(name: &str, description: &str, strategy: SpecializedStrategy) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            source: ToolSource::Core,
            implementation: ToolImplementation::Specialized(strategy),
        }
    }

    // Create a Core tool with standard logic (e.g. SearchSploit)
    pub fn core_standard(name: &str, description: &str, spec: ToolSpecification) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            source: ToolSource::Core,
            implementation: ToolImplementation::Standard(spec),
        }
    }

    // Create a User tool (always standard logic)
    pub fn user_created(name: &str, description: &str, spec: ToolSpecification) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            source: ToolSource::User,
            implementation: ToolImplementation::Standard(spec),
        }
    }
    
    pub fn add_placeholder() -> Self {
        Self {
            name: "[+] Add New Custom Tool".to_string(),
            description: "Define a new tool".to_string(),
            source: ToolSource::User,
            implementation: ToolImplementation::PlaceholderAdd,
        }
    }
}