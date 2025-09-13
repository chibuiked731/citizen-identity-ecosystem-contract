;; Privacy Protection and Data Minimization Smart Contract
;; This contract enforces privacy-preserving operations and implements data minimization principles
;; providing consent management, data access controls, and audit logging

;; Error constants
(define-constant ERR-UNAUTHORIZED (err u200))
(define-constant ERR-USER-NOT-FOUND (err u201))
(define-constant ERR-CONSENT-NOT-FOUND (err u202))
(define-constant ERR-CONSENT-ALREADY-EXISTS (err u203))
(define-constant ERR-INVALID-PERMISSION (err u204))
(define-constant ERR-CONSENT-EXPIRED (err u205))
(define-constant ERR-DATA-REQUEST-NOT-FOUND (err u206))
(define-constant ERR-INSUFFICIENT-PRIVACY-LEVEL (err u207))
(define-constant ERR-AUDIT-LOG-FULL (err u208))
(define-constant ERR-INVALID-PROOF (err u209))

;; Contract constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant MAX-USERS u1000000)
(define-constant MAX-CONSENT-RECORDS u10000000)
(define-constant MAX-AUDIT-LOGS u50000000)
(define-constant DEFAULT-CONSENT-DURATION u525600) ;; ~1 year in blocks
(define-constant MIN-PRIVACY-LEVEL u1)
(define-constant MAX-PRIVACY-LEVEL u5)

;; Data variables
(define-data-var user-counter uint u0)
(define-data-var consent-counter uint u0)
(define-data-var audit-log-counter uint u0)
(define-data-var contract-paused bool false)
(define-data-var global-privacy-policy-version uint u1)

;; Privacy level constants
(define-constant PRIVACY-LEVEL-PUBLIC u1)
(define-constant PRIVACY-LEVEL-RESTRICTED u2)
(define-constant PRIVACY-LEVEL-CONFIDENTIAL u3)
(define-constant PRIVACY-LEVEL-SECRET u4)
(define-constant PRIVACY-LEVEL-TOP-SECRET u5)

;; Data type constants
(define-constant DATA-TYPE-PERSONAL "PERSONAL")
(define-constant DATA-TYPE-BIOMETRIC "BIOMETRIC")
(define-constant DATA-TYPE-FINANCIAL "FINANCIAL")
(define-constant DATA-TYPE-HEALTH "HEALTH")
(define-constant DATA-TYPE-LOCATION "LOCATION")

;; User privacy preferences
(define-map user-privacy-preferences
    { user-id: uint }
    {
        owner: principal,
        created-at: uint,
        updated-at: uint,
        default-privacy-level: uint,
        data-retention-period: uint,
        audit-enabled: bool,
        notification-enabled: bool,
        anonymization-required: bool
    }
)

;; Principal to user ID mapping
(define-map principal-to-user
    { owner: principal }
    { user-id: uint }
)

;; Consent management
(define-map consent-records
    { consent-id: uint }
    {
        user-id: uint,
        data-requester: principal,
        data-types: (list 10 (string-ascii 20)),
        purpose: (string-ascii 200),
        granted-at: uint,
        expires-at: uint,
        privacy-level: uint,
        active: bool,
        usage-count: uint,
        max-usage-count: uint
    }
)

;; User consent mapping for quick lookups
(define-map user-consents
    { user-id: uint, data-requester: principal }
    { consent-id: uint, active: bool }
)

;; Data access requests
(define-map data-access-requests
    { request-id: uint }
    {
        requester: principal,
        user-id: uint,
        data-types: (list 10 (string-ascii 20)),
        purpose: (string-ascii 200),
        requested-at: uint,
        approved: bool,
        processed-at: (optional uint),
        privacy-level: uint
    }
)

;; Audit logs for data access
(define-map audit-logs
    { log-id: uint }
    {
        user-id: uint,
        data-requester: principal,
        action: (string-ascii 50),
        data-types: (list 10 (string-ascii 20)),
        timestamp: uint,
        privacy-level: uint,
        consent-id: (optional uint),
        success: bool,
        metadata: (string-ascii 500)
    }
)

;; Zero-knowledge proof verification records
(define-map zk-proof-verifications
    { verification-id: uint }
    {
        user-id: uint,
        verifier: principal,
        proof-hash: (buff 32),
        verified-at: uint,
        proof-type: (string-ascii 50),
        valid: bool
    }
)

;; Data processors registry
(define-map authorized-processors
    { processor: principal }
    {
        authorized: bool,
        authorized-at: uint,
        processor-name: (string-ascii 100),
        privacy-compliance-level: uint,
        data-processed-count: uint
    }
)

;; Public function: Set user privacy preferences
(define-public (set-privacy-preferences 
    (default-privacy-level uint)
    (data-retention-period uint)
    (audit-enabled bool)
    (notification-enabled bool)
    (anonymization-required bool)
)
    (let (
        (current-user-count (var-get user-counter))
        (existing-user (map-get? principal-to-user { owner: tx-sender }))
        (user-id (match existing-user
            user-data (get user-id user-data)
            (+ current-user-count u1)
        ))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (and (>= default-privacy-level MIN-PRIVACY-LEVEL) (<= default-privacy-level MAX-PRIVACY-LEVEL)) ERR-INVALID-PERMISSION)
        (asserts! (> data-retention-period u0) ERR-INVALID-PERMISSION)
        
        ;; Create or update user privacy preferences
        (map-set user-privacy-preferences
            { user-id: user-id }
            {
                owner: tx-sender,
                created-at: (match existing-user some-data (get created-at (unwrap-panic (map-get? user-privacy-preferences { user-id: user-id }))) block-height),
                updated-at: block-height,
                default-privacy-level: default-privacy-level,
                data-retention-period: data-retention-period,
                audit-enabled: audit-enabled,
                notification-enabled: notification-enabled,
                anonymization-required: anonymization-required
            }
        )
        
        ;; Map principal to user ID if new user
        (if (is-none existing-user)
            (begin
                (map-set principal-to-user { owner: tx-sender } { user-id: user-id })
                (var-set user-counter user-id)
            )
            true
        )
        
        (ok user-id)
    )
)

;; Public function: Request data access
(define-public (request-data-access 
    (user-id uint)
    (data-types (list 10 (string-ascii 20)))
    (purpose (string-ascii 200))
    (required-privacy-level uint)
)
    (let (
        (user-data (map-get? user-privacy-preferences { user-id: user-id }))
        (processor-data (map-get? authorized-processors { processor: tx-sender }))
        (request-id (+ (var-get audit-log-counter) u1))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-some user-data) ERR-USER-NOT-FOUND)
        (asserts! (is-some processor-data) ERR-UNAUTHORIZED)
        (asserts! (get authorized (unwrap-panic processor-data)) ERR-UNAUTHORIZED)
        (asserts! (and (>= required-privacy-level MIN-PRIVACY-LEVEL) (<= required-privacy-level MAX-PRIVACY-LEVEL)) ERR-INVALID-PERMISSION)
        (asserts! (> (len data-types) u0) ERR-INVALID-PERMISSION)
        
        ;; Check if processor meets privacy compliance level
        (asserts! (>= (get privacy-compliance-level (unwrap-panic processor-data)) required-privacy-level) ERR-INSUFFICIENT-PRIVACY-LEVEL)
        
        ;; Create data access request
        (map-set data-access-requests
            { request-id: request-id }
            {
                requester: tx-sender,
                user-id: user-id,
                data-types: data-types,
                purpose: purpose,
                requested-at: block-height,
                approved: false,
                processed-at: none,
                privacy-level: required-privacy-level
            }
        )
        
        ;; Log the access request
        (unwrap-panic (log-data-access user-id tx-sender "ACCESS_REQUEST" data-types none false "Data access requested"))
        
        (ok request-id)
    )
)

;; Public function: Grant consent for data access
(define-public (grant-consent 
    (data-requester principal)
    (data-types (list 10 (string-ascii 20)))
    (purpose (string-ascii 200))
    (consent-duration uint)
    (max-usage-count uint)
    (privacy-level uint)
)
    (let (
        (user-data (map-get? principal-to-user { owner: tx-sender }))
        (user-id (get user-id (unwrap-panic user-data)))
        (current-consent-count (var-get consent-counter))
        (new-consent-id (+ current-consent-count u1))
        (existing-consent (map-get? user-consents { user-id: user-id, data-requester: data-requester }))
        (expires-at (+ block-height consent-duration))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-some user-data) ERR-USER-NOT-FOUND)
        (asserts! (is-none existing-consent) ERR-CONSENT-ALREADY-EXISTS)
        (asserts! (and (>= privacy-level MIN-PRIVACY-LEVEL) (<= privacy-level MAX-PRIVACY-LEVEL)) ERR-INVALID-PERMISSION)
        (asserts! (> consent-duration u0) ERR-INVALID-PERMISSION)
        (asserts! (> max-usage-count u0) ERR-INVALID-PERMISSION)
        
        ;; Create consent record
        (map-set consent-records
            { consent-id: new-consent-id }
            {
                user-id: user-id,
                data-requester: data-requester,
                data-types: data-types,
                purpose: purpose,
                granted-at: block-height,
                expires-at: expires-at,
                privacy-level: privacy-level,
                active: true,
                usage-count: u0,
                max-usage-count: max-usage-count
            }
        )
        
        ;; Map user consent for quick lookup
        (map-set user-consents
            { user-id: user-id, data-requester: data-requester }
            { consent-id: new-consent-id, active: true }
        )
        
        ;; Update counter
        (var-set consent-counter new-consent-id)
        
        ;; Log consent granted
        (unwrap-panic (log-data-access user-id data-requester "CONSENT_GRANTED" data-types (some new-consent-id) true "Consent granted for data access"))
        
        (ok new-consent-id)
    )
)

;; Public function: Revoke consent
(define-public (revoke-consent (data-requester principal))
    (let (
        (user-data (map-get? principal-to-user { owner: tx-sender }))
        (user-id (get user-id (unwrap-panic user-data)))
        (consent-mapping (map-get? user-consents { user-id: user-id, data-requester: data-requester }))
        (consent-id (get consent-id (unwrap-panic consent-mapping)))
        (consent-data (map-get? consent-records { consent-id: consent-id }))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-some user-data) ERR-USER-NOT-FOUND)
        (asserts! (is-some consent-mapping) ERR-CONSENT-NOT-FOUND)
        (asserts! (get active (unwrap-panic consent-mapping)) ERR-CONSENT-NOT-FOUND)
        
        ;; Revoke consent
        (map-set consent-records
            { consent-id: consent-id }
            (merge (unwrap-panic consent-data) { active: false })
        )
        
        ;; Update user consent mapping
        (map-set user-consents
            { user-id: user-id, data-requester: data-requester }
            { consent-id: consent-id, active: false }
        )
        
        ;; Log consent revocation
        (unwrap-panic (log-data-access user-id data-requester "CONSENT_REVOKED" (get data-types (unwrap-panic consent-data)) (some consent-id) true "Consent revoked"))
        
        (ok true)
    )
)

;; Public function: Process data access with consent verification
(define-public (process-data-access (user-id uint) (data-types (list 10 (string-ascii 20))))
    (let (
        (user-data (map-get? user-privacy-preferences { user-id: user-id }))
        (consent-mapping (map-get? user-consents { user-id: user-id, data-requester: tx-sender }))
        (consent-id (get consent-id (unwrap-panic consent-mapping)))
        (consent-data (map-get? consent-records { consent-id: consent-id }))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-some user-data) ERR-USER-NOT-FOUND)
        (asserts! (is-some consent-mapping) ERR-CONSENT-NOT-FOUND)
        (asserts! (get active (unwrap-panic consent-mapping)) ERR-CONSENT-NOT-FOUND)
        
        (let (
            (consent (unwrap-panic consent-data))
        )
            ;; Verify consent is still valid
            (asserts! (get active consent) ERR-CONSENT-NOT-FOUND)
            (asserts! (> (get expires-at consent) block-height) ERR-CONSENT-EXPIRED)
            (asserts! (< (get usage-count consent) (get max-usage-count consent)) ERR-CONSENT-EXPIRED)
            
            ;; Update usage count
            (map-set consent-records
                { consent-id: consent-id }
                (merge consent { usage-count: (+ (get usage-count consent) u1) })
            )
            
            ;; Log data access
            (unwrap-panic (log-data-access user-id tx-sender "DATA_ACCESS" data-types (some consent-id) true "Data accessed with valid consent"))
            
            (ok true)
        )
    )
)

;; Public function: Verify zero-knowledge proof
(define-public (verify-zk-proof (user-id uint) (proof-hash (buff 32)) (proof-type (string-ascii 50)))
    (let (
        (user-data (map-get? user-privacy-preferences { user-id: user-id }))
        (verification-id (+ (var-get audit-log-counter) u1))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-some user-data) ERR-USER-NOT-FOUND)
        (asserts! (> (len proof-hash) u0) ERR-INVALID-PROOF)
        
        ;; For demonstration, we'll assume proof is valid if hash is provided
        ;; In a real implementation, this would involve complex cryptographic verification
        (let (
            (proof-valid (> (len proof-hash) u0))
        )
            ;; Record proof verification
            (map-set zk-proof-verifications
                { verification-id: verification-id }
                {
                    user-id: user-id,
                    verifier: tx-sender,
                    proof-hash: proof-hash,
                    verified-at: block-height,
                    proof-type: proof-type,
                    valid: proof-valid
                }
            )
            
            ;; Log proof verification
            (unwrap-panic (log-data-access user-id tx-sender "PROOF_VERIFICATION" (list "PROOF") none proof-valid "Zero-knowledge proof verified"))
            
            (ok proof-valid)
        )
    )
)

;; Admin function: Authorize data processor
(define-public (authorize-processor (processor principal) (processor-name (string-ascii 100)) (privacy-compliance-level uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (asserts! (and (>= privacy-compliance-level MIN-PRIVACY-LEVEL) (<= privacy-compliance-level MAX-PRIVACY-LEVEL)) ERR-INVALID-PERMISSION)
        
        (map-set authorized-processors
            { processor: processor }
            {
                authorized: true,
                authorized-at: block-height,
                processor-name: processor-name,
                privacy-compliance-level: privacy-compliance-level,
                data-processed-count: u0
            }
        )
        
        (ok true)
    )
)

;; Private function: Log data access activity
(define-private (log-data-access 
    (user-id uint)
    (data-requester principal)
    (action (string-ascii 50))
    (data-types (list 10 (string-ascii 20)))
    (consent-id (optional uint))
    (success bool)
    (metadata (string-ascii 500))
)
    (let (
        (current-log-count (var-get audit-log-counter))
        (new-log-id (+ current-log-count u1))
        (user-data (map-get? user-privacy-preferences { user-id: user-id }))
    )
        (asserts! (< current-log-count MAX-AUDIT-LOGS) ERR-AUDIT-LOG-FULL)
        
        ;; Only log if user has audit enabled or if it's a critical action
        (if (or 
            (match user-data
                user-prefs (get audit-enabled user-prefs)
                true
            )
            (or (is-eq action "CONSENT_REVOKED") (is-eq action "UNAUTHORIZED_ACCESS"))
        )
            (begin
                (map-set audit-logs
                    { log-id: new-log-id }
                    {
                        user-id: user-id,
                        data-requester: data-requester,
                        action: action,
                        data-types: data-types,
                        timestamp: block-height,
                        privacy-level: (match user-data
                            user-prefs (get default-privacy-level user-prefs)
                            PRIVACY-LEVEL-CONFIDENTIAL
                        ),
                        consent-id: consent-id,
                        success: success,
                        metadata: metadata
                    }
                )
                (var-set audit-log-counter new-log-id)
            )
            true
        )
        
        (ok true)
    )
)

;; Read-only function: Get user privacy preferences
(define-read-only (get-user-privacy-preferences (user-id uint))
    (map-get? user-privacy-preferences { user-id: user-id })
)

;; Read-only function: Get consent details
(define-read-only (get-consent (consent-id uint))
    (map-get? consent-records { consent-id: consent-id })
)

;; Read-only function: Check if consent is valid
(define-read-only (is-consent-valid (user-id uint) (data-requester principal))
    (match (map-get? user-consents { user-id: user-id, data-requester: data-requester })
        consent-mapping 
        (let (
            (consent-data (map-get? consent-records { consent-id: (get consent-id consent-mapping) }))
        )
            (match consent-data
                consent 
                (and 
                    (get active consent)
                    (> (get expires-at consent) block-height)
                    (< (get usage-count consent) (get max-usage-count consent))
                )
                false
            )
        )
        false
    )
)

;; Read-only function: Get audit trail for user
(define-read-only (get-user-audit-trail (user-id uint))
    ;; In a full implementation, this would return a filtered list of audit logs
    ;; For now, we return the audit log counter as a simple metric
    (var-get audit-log-counter)
)

;; Read-only function: Check if processor is authorized
(define-read-only (is-authorized-processor (processor principal))
    (match (map-get? authorized-processors { processor: processor })
        processor-data (get authorized processor-data)
        false
    )
)

;; Read-only function: Get contract statistics
(define-read-only (get-privacy-contract-stats)
    {
        total-users: (var-get user-counter),
        total-consents: (var-get consent-counter),
        total-audit-logs: (var-get audit-log-counter),
        contract-paused: (var-get contract-paused),
        privacy-policy-version: (var-get global-privacy-policy-version)
    }
)
