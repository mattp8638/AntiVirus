#[derive(Debug, Clone)]
pub struct PipelineStatus {
    pub edr_ready: bool,
    pub siem_ready: bool,
    pub rmm_ready: bool,
    pub vulnerability_ready: bool,
}

impl PipelineStatus {
    pub fn new() -> Self {
        Self {
            edr_ready: false,
            siem_ready: false,
            rmm_ready: false,
            vulnerability_ready: false,
        }
    }

    pub fn mark_edr_ready(&mut self) {
        self.edr_ready = true;
    }

    pub fn mark_siem_ready(&mut self) {
        self.siem_ready = true;
    }

    pub fn mark_rmm_ready(&mut self) {
        self.rmm_ready = true;
    }

    pub fn mark_vulnerability_ready(&mut self) {
        self.vulnerability_ready = true;
    }

    pub fn is_fully_ready(&self) -> bool {
        self.edr_ready && self.siem_ready && self.rmm_ready && self.vulnerability_ready
    }
}
