pub mod agentguard {
    pub mod common {
        tonic::include_proto!("agentguard.common");
    }

    pub mod registry {
        tonic::include_proto!("agentguard.registry");
    }

    pub mod intent {
        tonic::include_proto!("agentguard.intent");
    }

    pub mod policy {
        tonic::include_proto!("agentguard.policy");
    }

    pub mod token {
        tonic::include_proto!("agentguard.token");
    }

    pub mod kill {
        tonic::include_proto!("agentguard.kill");
    }

    pub mod risk {
        tonic::include_proto!("agentguard.risk");
    }

    pub mod control {
        tonic::include_proto!("agentguard.control");
    }
}
