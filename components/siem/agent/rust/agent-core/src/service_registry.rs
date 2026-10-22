#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub name: String,
    pub version: String,
    pub ipc_endpoint: String,
}

#[derive(Debug, Default)]
pub struct ServiceRegistry {
    services: Vec<ServiceDescriptor>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self { services: Vec::new() }
    }

    pub fn register(&mut self, descriptor: ServiceDescriptor) {
        self.services.push(descriptor);
    }

    pub fn list(&self) -> &[ServiceDescriptor] {
        &self.services
    }
}
