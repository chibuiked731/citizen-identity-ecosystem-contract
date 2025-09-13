;; Digital Identity and Credential Management Smart Contract
;; This contract manages citizen digital identities and verifiable credentials
;; providing secure identity registration, credential issuance, and verification

;; Error constants
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-IDENTITY-EXISTS (err u101))
(define-constant ERR-IDENTITY-NOT-FOUND (err u102))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u103))
(define-constant ERR-CREDENTIAL-REVOKED (err u104))
(define-constant ERR-INVALID-INPUT (err u105))
(define-constant ERR-INSUFFICIENT-PERMISSIONS (err u106))
(define-constant ERR-CREDENTIAL-EXPIRED (err u107))
(define-constant ERR-ISSUER-NOT-AUTHORIZED (err u108))

;; Contract constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant MAX-IDENTITY-COUNT u1000000)
(define-constant MAX-CREDENTIAL-COUNT u5000000)
(define-constant CREDENTIAL-VALIDITY-PERIOD u52560000) ;; ~10 years in blocks

;; Data variables
(define-data-var identity-counter uint u0)
(define-data-var credential-counter uint u0)
(define-data-var contract-paused bool false)

;; Identity status enumeration
(define-constant IDENTITY-STATUS-ACTIVE u1)
(define-constant IDENTITY-STATUS-SUSPENDED u2)
(define-constant IDENTITY-STATUS-REVOKED u3)

;; Credential status enumeration
(define-constant CREDENTIAL-STATUS-VALID u1)
(define-constant CREDENTIAL-STATUS-EXPIRED u2)
(define-constant CREDENTIAL-STATUS-REVOKED u3)

;; Data maps for identity management
(define-map identities
    { identity-id: uint }
    {
        owner: principal,
        created-at: uint,
        updated-at: uint,
        status: uint,
        identity-hash: (buff 32),
        metadata-uri: (string-ascii 256),
        verified: bool,
        verification-count: uint
    }
)

;; Principal to identity ID mapping
(define-map principal-to-identity
    { owner: principal }
    { identity-id: uint }
)

;; Authorized issuers map
(define-map authorized-issuers
    { issuer: principal }
    {
        authorized: bool,
        authorized-at: uint,
        issuer-name: (string-ascii 100),
        credentials-issued: uint
    }
)

;; Credentials map
(define-map credentials
    { credential-id: uint }
    {
        identity-id: uint,
        issuer: principal,
        issued-at: uint,
        expires-at: uint,
        status: uint,
        credential-type: (string-ascii 50),
        credential-hash: (buff 32),
        metadata-uri: (string-ascii 256)
    }
)

;; Identity credentials mapping
(define-map identity-credentials
    { identity-id: uint, credential-type: (string-ascii 50) }
    { credential-id: uint, active: bool }
)

;; Multi-signature approvals for critical operations
(define-map multisig-approvals
    { operation-id: (buff 32) }
    {
        operation-type: (string-ascii 50),
        approvals-count: uint,
        required-approvals: uint,
        executed: bool,
        created-at: uint
    }
)

;; Public function: Register a new digital identity
(define-public (register-identity (identity-hash (buff 32)) (metadata-uri (string-ascii 256)))
    (let (
        (current-identity-count (var-get identity-counter))
        (new-identity-id (+ current-identity-count u1))
        (existing-identity (map-get? principal-to-identity { owner: tx-sender }))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-none existing-identity) ERR-IDENTITY-EXISTS)
        (asserts! (< current-identity-count MAX-IDENTITY-COUNT) ERR-INVALID-INPUT)
        (asserts! (> (len identity-hash) u0) ERR-INVALID-INPUT)
        
        ;; Create new identity record
        (map-set identities
            { identity-id: new-identity-id }
            {
                owner: tx-sender,
                created-at: block-height,
                updated-at: block-height,
                status: IDENTITY-STATUS-ACTIVE,
                identity-hash: identity-hash,
                metadata-uri: metadata-uri,
                verified: false,
                verification-count: u0
            }
        )
        
        ;; Map principal to identity ID
        (map-set principal-to-identity
            { owner: tx-sender }
            { identity-id: new-identity-id }
        )
        
        ;; Update counter
        (var-set identity-counter new-identity-id)
        
        (ok new-identity-id)
    )
)

;; Public function: Issue a verifiable credential
(define-public (issue-credential 
    (identity-id uint) 
    (credential-type (string-ascii 50))
    (credential-hash (buff 32))
    (metadata-uri (string-ascii 256))
    (validity-period uint)
)
    (let (
        (current-credential-count (var-get credential-counter))
        (new-credential-id (+ current-credential-count u1))
        (identity-data (map-get? identities { identity-id: identity-id }))
        (issuer-data (map-get? authorized-issuers { issuer: tx-sender }))
        (expires-at (+ block-height validity-period))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-some identity-data) ERR-IDENTITY-NOT-FOUND)
        (asserts! (is-some issuer-data) ERR-ISSUER-NOT-AUTHORIZED)
        (asserts! (get authorized (unwrap-panic issuer-data)) ERR-ISSUER-NOT-AUTHORIZED)
        (asserts! (< current-credential-count MAX-CREDENTIAL-COUNT) ERR-INVALID-INPUT)
        (asserts! (> (len credential-hash) u0) ERR-INVALID-INPUT)
        (asserts! (<= validity-period CREDENTIAL-VALIDITY-PERIOD) ERR-INVALID-INPUT)
        
        ;; Verify identity is active
        (asserts! (is-eq (get status (unwrap-panic identity-data)) IDENTITY-STATUS-ACTIVE) ERR-UNAUTHORIZED)
        
        ;; Create credential record
        (map-set credentials
            { credential-id: new-credential-id }
            {
                identity-id: identity-id,
                issuer: tx-sender,
                issued-at: block-height,
                expires-at: expires-at,
                status: CREDENTIAL-STATUS-VALID,
                credential-type: credential-type,
                credential-hash: credential-hash,
                metadata-uri: metadata-uri
            }
        )
        
        ;; Link credential to identity
        (map-set identity-credentials
            { identity-id: identity-id, credential-type: credential-type }
            { credential-id: new-credential-id, active: true }
        )
        
        ;; Update issuer statistics
        (map-set authorized-issuers
            { issuer: tx-sender }
            (merge (unwrap-panic issuer-data) { credentials-issued: (+ (get credentials-issued (unwrap-panic issuer-data)) u1) })
        )
        
        ;; Update counters
        (var-set credential-counter new-credential-id)
        
        (ok new-credential-id)
    )
)

;; Public function: Verify a credential
(define-public (verify-credential (credential-id uint))
    (let (
        (credential-data (map-get? credentials { credential-id: credential-id }))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-some credential-data) ERR-CREDENTIAL-NOT-FOUND)
        
        (let (
            (credential (unwrap-panic credential-data))
            (identity-data (map-get? identities { identity-id: (get identity-id credential) }))
        )
            (asserts! (is-some identity-data) ERR-IDENTITY-NOT-FOUND)
            
            ;; Check if credential is still valid
            (asserts! (is-eq (get status credential) CREDENTIAL-STATUS-VALID) ERR-CREDENTIAL-REVOKED)
            (asserts! (> (get expires-at credential) block-height) ERR-CREDENTIAL-EXPIRED)
            
            ;; Check if identity is active
            (asserts! (is-eq (get status (unwrap-panic identity-data)) IDENTITY-STATUS-ACTIVE) ERR-UNAUTHORIZED)
            
            ;; Update verification count for identity
            (map-set identities
                { identity-id: (get identity-id credential) }
                (merge (unwrap-panic identity-data) 
                    { 
                        verification-count: (+ (get verification-count (unwrap-panic identity-data)) u1),
                        updated-at: block-height
                    }
                )
            )
            
            (ok true)
        )
    )
)

;; Public function: Revoke a credential (only by issuer or identity owner)
(define-public (revoke-credential (credential-id uint))
    (let (
        (credential-data (map-get? credentials { credential-id: credential-id }))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-some credential-data) ERR-CREDENTIAL-NOT-FOUND)
        
        (let (
            (credential (unwrap-panic credential-data))
            (identity-data (map-get? identities { identity-id: (get identity-id credential) }))
        )
            (asserts! (is-some identity-data) ERR-IDENTITY-NOT-FOUND)
            
            ;; Verify caller is either issuer or identity owner
            (asserts! (or 
                (is-eq tx-sender (get issuer credential))
                (is-eq tx-sender (get owner (unwrap-panic identity-data)))
            ) ERR-UNAUTHORIZED)
            
            ;; Update credential status
            (map-set credentials
                { credential-id: credential-id }
                (merge credential { status: CREDENTIAL-STATUS-REVOKED })
            )
            
            ;; Deactivate in identity-credentials mapping
            (map-set identity-credentials
                { identity-id: (get identity-id credential), credential-type: (get credential-type credential) }
                { credential-id: credential-id, active: false }
            )
            
            (ok true)
        )
    )
)

;; Public function: Update identity metadata (only by owner)
(define-public (update-identity (identity-id uint) (new-metadata-uri (string-ascii 256)))
    (let (
        (identity-data (map-get? identities { identity-id: identity-id }))
    )
        (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
        (asserts! (is-some identity-data) ERR-IDENTITY-NOT-FOUND)
        (asserts! (is-eq tx-sender (get owner (unwrap-panic identity-data))) ERR-UNAUTHORIZED)
        
        ;; Update identity metadata
        (map-set identities
            { identity-id: identity-id }
            (merge (unwrap-panic identity-data) 
                {
                    metadata-uri: new-metadata-uri,
                    updated-at: block-height
                }
            )
        )
        
        (ok true)
    )
)

;; Admin function: Authorize credential issuer
(define-public (authorize-issuer (issuer principal) (issuer-name (string-ascii 100)))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        
        (map-set authorized-issuers
            { issuer: issuer }
            {
                authorized: true,
                authorized-at: block-height,
                issuer-name: issuer-name,
                credentials-issued: u0
            }
        )
        
        (ok true)
    )
)

;; Admin function: Revoke issuer authorization
(define-public (revoke-issuer-authorization (issuer principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        
        (map-set authorized-issuers
            { issuer: issuer }
            {
                authorized: false,
                authorized-at: block-height,
                issuer-name: "",
                credentials-issued: u0
            }
        )
        
        (ok true)
    )
)

;; Read-only function: Get identity details
(define-read-only (get-identity (identity-id uint))
    (map-get? identities { identity-id: identity-id })
)

;; Read-only function: Get credential details
(define-read-only (get-credential (credential-id uint))
    (map-get? credentials { credential-id: credential-id })
)

;; Read-only function: Get identity ID by principal
(define-read-only (get-identity-by-principal (owner principal))
    (map-get? principal-to-identity { owner: owner })
)

;; Read-only function: Check if issuer is authorized
(define-read-only (is-authorized-issuer (issuer principal))
    (match (map-get? authorized-issuers { issuer: issuer })
        issuer-data (get authorized issuer-data)
        false
    )
)

;; Read-only function: Get contract statistics
(define-read-only (get-contract-stats)
    {
        total-identities: (var-get identity-counter),
        total-credentials: (var-get credential-counter),
        contract-paused: (var-get contract-paused)
    }
)
