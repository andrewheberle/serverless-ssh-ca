import { IRequestStrict } from "itty-router"

// Device code flow types
export type DeviceCodeResponse = {
    device_code: string
    user_code: string
    verification_uri: string
    verification_uri_complete: string
    expires_in: number
    interval: number
};

export type DeviceCodeTokenRequest = {
    device_code: string
    grant_type: string
};

export type HostInfo = {
    public_key: string
    fingerprint: string
    hostname: string
    ip_addresses: string[]
    additional_principals: string[]
    principals: string[]
};

export type DeviceFlowState = {
    user_code: string
    status: "pending" | "awaiting_host_info" | "awaiting_approval" | "approved" | "denied"
    created_at: number
    host_info: HostInfo | null
    admin_email: string | null
    approved_at: number | null
}

export type HostInfoSubmission = {
    device_code: string
    public_key: string
    hostname: string
    ip_addresses: string[]
    additional_principals?: string[]
}

export type HostCertificateRequest = {
    device_code: string
    public_key: string
}

export type HostCertificateRenewalRequest = {
    current_certificate: string
    public_key: string
    challenge_response: string
}

export type HostCertificateResponse = {
    certificate: string
    principals: string[]
    valid_after: number
    valid_before: number
    key_id: string
}

// Admin request type
export type HostAdminRequest = {
    email: string
    groups?: string[]
} & IRequestStrict
