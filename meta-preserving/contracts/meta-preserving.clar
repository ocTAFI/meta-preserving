;; MetaPreserving - Zero-Knowledge Identity Verification System
;; A simplified implementation focusing on credential management and verification

;; Error constants
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u101))
(define-constant ERR-CREDENTIAL-EXPIRED (err u102))
(define-constant ERR-INVALID-VALIDATOR (err u103))
(define-constant ERR-INSUFFICIENT-STAKE (err u104))
(define-constant ERR-ALREADY-EXISTS (err u105))

;; Contract constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant MIN-VALIDATOR-STAKE u1000000) ;; 1 STX minimum stake
(define-constant CREDENTIAL-VALIDITY-PERIOD u52560) ;; ~1 year in blocks (10 min blocks)

;; Data structures
(define-map credentials
  { credential-id: (buff 32) }
  {
    issuer: principal,
    subject-hash: (buff 32), ;; Hash of subject identity (zero-knowledge proof)
    attribute-type: (string-ascii 50),
    proof-hash: (buff 32), ;; Zero-knowledge proof commitment
    issued-at: uint,
    expires-at: uint,
    is-revoked: bool
  }
)

(define-map validators
  { validator: principal }
  {
    stake-amount: uint,
    reputation-score: uint,
    is-active: bool,
    registered-at: uint
  }
)

(define-map validator-signatures
  { credential-id: (buff 32), validator: principal }
  { signature-hash: (buff 32), signed-at: uint }
)

(define-map reputation-scores
  { subject-hash: (buff 32) }
  { score: uint, last-updated: uint }
)

;; Data variables
(define-data-var total-validators uint u0)
(define-data-var min-validator-threshold uint u3)

;; Public functions

;; Register as a validator with required stake
(define-public (register-validator (stake-amount uint))
  (let (
    (validator tx-sender)
  )
    (asserts! (>= stake-amount MIN-VALIDATOR-STAKE) ERR-INSUFFICIENT-STAKE)
    (asserts! (is-none (map-get? validators {validator: validator})) ERR-ALREADY-EXISTS)
    
    ;; Transfer stake to contract
    (try! (stx-transfer? stake-amount validator (as-contract tx-sender)))
    
    ;; Register validator
    (map-set validators
      {validator: validator}
      {
        stake-amount: stake-amount,
        reputation-score: u100, ;; Starting reputation
        is-active: true,
        registered-at: block-height
      }
    )
    
    (var-set total-validators (+ (var-get total-validators) u1))
    (ok true)
  )
)

;; Issue a new credential (only by registered validators)
(define-public (issue-credential 
  (credential-id (buff 32))
  (subject-hash (buff 32))
  (attribute-type (string-ascii 50))
  (proof-hash (buff 32))
)
  (let (
    (validator tx-sender)
    (validator-info (unwrap! (map-get? validators {validator: validator}) ERR-INVALID-VALIDATOR))
    (expires-at (+ block-height CREDENTIAL-VALIDITY-PERIOD))
  )
    ;; Verify validator is active
    (asserts! (get is-active validator-info) ERR-INVALID-VALIDATOR)
    
    ;; Check credential doesn't already exist
    (asserts! (is-none (map-get? credentials {credential-id: credential-id})) ERR-ALREADY-EXISTS)
    
    ;; Issue credential
    (map-set credentials
      {credential-id: credential-id}
      {
        issuer: validator,
        subject-hash: subject-hash,
        attribute-type: attribute-type,
        proof-hash: proof-hash,
        issued-at: block-height,
        expires-at: expires-at,
        is-revoked: false
      }
    )
    
    (ok credential-id)
  )
)

;; Add validator signature to credential (threshold signatures)
(define-public (sign-credential 
  (credential-id (buff 32))
  (signature-hash (buff 32))
)
  (let (
    (validator tx-sender)
    (validator-info (unwrap! (map-get? validators {validator: validator}) ERR-INVALID-VALIDATOR))
    (credential-info (unwrap! (map-get? credentials {credential-id: credential-id}) ERR-CREDENTIAL-NOT-FOUND))
  )
    ;; Verify validator is active
    (asserts! (get is-active validator-info) ERR-INVALID-VALIDATOR)
    
    ;; Verify credential is not expired or revoked
    (asserts! (< block-height (get expires-at credential-info)) ERR-CREDENTIAL-EXPIRED)
    (asserts! (not (get is-revoked credential-info)) ERR-CREDENTIAL-EXPIRED)
    
    ;; Add signature
    (map-set validator-signatures
      {credential-id: credential-id, validator: validator}
      {signature-hash: signature-hash, signed-at: block-height}
    )
    
    (ok true)
  )
)

;; Verify a credential and its signatures
(define-public (verify-credential (credential-id (buff 32)))
  (let (
    (credential-info (unwrap! (map-get? credentials {credential-id: credential-id}) ERR-CREDENTIAL-NOT-FOUND))
  )
    ;; Check if credential is valid and not expired
    (asserts! (< block-height (get expires-at credential-info)) ERR-CREDENTIAL-EXPIRED)
    (asserts! (not (get is-revoked credential-info)) ERR-CREDENTIAL-EXPIRED)
    
    (ok {
      subject-hash: (get subject-hash credential-info),
      attribute-type: (get attribute-type credential-info),
      proof-hash: (get proof-hash credential-info),
      expires-at: (get expires-at credential-info),
      is-valid: true
    })
  )
)

;; Update reputation score (zero-knowledge aggregation)
(define-public (update-reputation 
  (subject-hash (buff 32))
  (score-delta uint)
  (is-positive bool)
)
  (let (
    (validator tx-sender)
    (validator-info (unwrap! (map-get? validators {validator: validator}) ERR-INVALID-VALIDATOR))
    (current-reputation (default-to {score: u0, last-updated: u0} 
                         (map-get? reputation-scores {subject-hash: subject-hash})))
  )
    ;; Verify validator is active
    (asserts! (get is-active validator-info) ERR-INVALID-VALIDATOR)
    
    ;; Calculate new score
    (let (
      (current-score (get score current-reputation))
      (new-score (if is-positive 
                    (+ current-score score-delta)
                    (if (>= current-score score-delta) 
                        (- current-score score-delta) 
                        u0)))
    )
      ;; Update reputation
      (map-set reputation-scores
        {subject-hash: subject-hash}
        {score: new-score, last-updated: block-height}
      )
      
      (ok new-score)
    )
  )
)

;; Revoke a credential (only by issuer or contract owner)
(define-public (revoke-credential (credential-id (buff 32)))
  (let (
    (credential-info (unwrap! (map-get? credentials {credential-id: credential-id}) ERR-CREDENTIAL-NOT-FOUND))
    (caller tx-sender)
  )
    ;; Only issuer or contract owner can revoke
    (asserts! (or (is-eq caller (get issuer credential-info)) 
                  (is-eq caller CONTRACT-OWNER)) ERR-UNAUTHORIZED)
    
    ;; Mark as revoked
    (map-set credentials
      {credential-id: credential-id}
      (merge credential-info {is-revoked: true})
    )
    
    (ok true)
  )
)

;; Read-only functions

;; Get credential information
(define-read-only (get-credential (credential-id (buff 32)))
  (map-get? credentials {credential-id: credential-id})
)

;; Get validator information
(define-read-only (get-validator (validator principal))
  (map-get? validators {validator: validator})
)

;; Get reputation score
(define-read-only (get-reputation (subject-hash (buff 32)))
  (map-get? reputation-scores {subject-hash: subject-hash})
)

;; Check if credential is valid (not expired and not revoked)
(define-read-only (is-credential-valid (credential-id (buff 32)))
  (match (map-get? credentials {credential-id: credential-id})
    credential-info (and 
                      (< block-height (get expires-at credential-info))
                      (not (get is-revoked credential-info)))
    false
  )
)

;; Get validator signature for credential
(define-read-only (get-validator-signature 
  (credential-id (buff 32)) 
  (validator principal)
)
  (map-get? validator-signatures {credential-id: credential-id, validator: validator})
)

;; Get total number of validators
(define-read-only (get-total-validators)
  (var-get total-validators)
)

;; Get minimum validator threshold
(define-read-only (get-min-threshold)
  (var-get min-validator-threshold)
)

;; Administrative functions (contract owner only)

;; Update minimum validator threshold
(define-public (set-min-threshold (new-threshold uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    (var-set min-validator-threshold new-threshold)
    (ok true)
  )
)

;; Deactivate a validator (emergency function)
(define-public (deactivate-validator (validator principal))
  (let (
    (validator-info (unwrap! (map-get? validators {validator: validator}) ERR-INVALID-VALIDATOR))
  )
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    
    (map-set validators
      {validator: validator}
      (merge validator-info {is-active: false})
    )
    
    (ok true)
  )
)