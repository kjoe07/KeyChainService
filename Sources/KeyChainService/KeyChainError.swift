//
//  File.swift
//  
//
//  Created by kjoe on 5/1/23.
//

import Foundation
enum KeyChainError: OSStatus, LocalizedError {
    case errSecUnimplemented
    case errSecDiskFull
    case errSecIO
    case errSecOpWr
    case errSecParam
    case errSecWrPerm
    case errSecAllocate
    case errSecUserCanceled
    case errSecBadReq
    
    case errSecInternalComponent
    case errSecCoreFoundationUnknown
    
    case errSecMissingEntitlement
    case errSecRestrictedAPI
    
    case errSecNotAvailable
    case errSecReadOnly
    case errSecAuthFailed
    case errSecNoSuchKeychain
    case errSecInvalidKeychain
    case errSecDuplicateKeychain
    case errSecDuplicateCallback
    case errSecInvalidCallback
    case errSecDuplicateItem
    case errSecItemNotFound
    case errSecBufferTooSmall
    case errSecDataTooLarge
    case errSecNoSuchAttr
    case errSecInvalidItemRef
    case errSecInvalidSearchRef
    case errSecNoSuchClass
    case errSecNoDefaultKeychain
    case errSecInteractionNotAllowed
    case errSecReadOnlyAttr
    case errSecWrongSecVersion
    case errSecKeySizeNotAllowed
    case errSecNoStorageModule
    case errSecNoCertificateModule
    case errSecNoPolicyModule
    case errSecInteractionRequired
    case errSecDataNotAvailable
    case errSecDataNotModifiable
    case errSecCreateChainFailed
    case errSecInvalidPrefsDomain
    case errSecInDarkWake
    
    case errSecACLNotSimple
    case errSecPolicyNotFound
    case errSecInvalidTrustSetting
    case errSecNoAccessForItem
    case errSecInvalidOwnerEdit
    case errSecTrustNotAvailable
    case errSecUnsupportedFormat
    case errSecUnknownFormat
    case errSecKeyIsSensitive
    case errSecMultiplePrivKeys
    case errSecPassphraseRequired
    case errSecInvalidPasswordRef
    case errSecInvalidTrustSettings
    case errSecNoTrustSettings
    case errSecPkcs12VerifyFailure
    case errSecNotSigner
    
    case errSecDecode
    
    case errSecServiceNotAvailable
    case errSecInsufficientClientID
    case errSecDeviceReset
    case errSecDeviceFailed
    case errSecAppleAddAppACLSubject
    case errSecApplePublicKeyIncomplete
    case errSecAppleSignatureMismatch
    case errSecAppleInvalidKeyStartDate
    case errSecAppleInvalidKeyEndDate
    case errSecConversionError
    case errSecAppleSSLv2Rollback
    case errSecQuotaExceeded
    case errSecFileTooBig
    case errSecInvalidDatabaseBlob
    case errSecInvalidKeyBlob
    case errSecIncompatibleDatabaseBlob
    case errSecIncompatibleKeyBlob
    case errSecHostNameMismatch
    case errSecUnknownCriticalExtensionFlag
    case errSecNoBasicConstraints
    case errSecNoBasicConstraintsCA
    case errSecInvalidAuthorityKeyID
    case errSecInvalidSubjectKeyID
    case errSecInvalidKeyUsageForPolicy
    case errSecInvalidExtendedKeyUsage
    case errSecInvalidIDLinkage
    case errSecPathLengthConstraintExceeded
    case errSecInvalidRoot
    case errSecCRLExpired
    case errSecCRLNotValidYet
    case errSecCRLNotFound
    case errSecCRLServerDown
    case errSecCRLBadURI
    case errSecUnknownCertExtension
    case errSecUnknownCRLExtension
    case errSecCRLNotTrusted
    case errSecCRLPolicyFailed
    case errSecIDPFailure
    case errSecSMIMEEmailAddressesNotFound
    case errSecSMIMEBadExtendedKeyUsage
    case errSecSMIMEBadKeyUsage
    case errSecSMIMEKeyUsageNotCritical
    case errSecSMIMENoEmailAddress
    case errSecSMIMESubjAltNameNotCritical
    case errSecSSLBadExtendedKeyUsage
    case errSecOCSPBadResponse
    case errSecOCSPBadRequest
    case errSecOCSPUnavailable
    case errSecOCSPStatusUnrecognized
    case errSecEndOfData
    case errSecIncompleteCertRevocationCheck
    case errSecNetworkFailure
    case errSecOCSPNotTrustedToAnchor
    case errSecRecordModified
    case errSecOCSPSignatureError
    case errSecOCSPNoSigner
    case errSecOCSPResponderMalformedReq
    case errSecOCSPResponderInternalError
    case errSecOCSPResponderTryLater
    case errSecOCSPResponderSignatureRequired
    case errSecOCSPResponderUnauthorized
    case errSecOCSPResponseNonceMismatch
    case errSecCodeSigningBadCertChainLength
    case errSecCodeSigningNoBasicConstraints
    case errSecCodeSigningBadPathLengthConstraint
    case errSecCodeSigningNoExtendedKeyUsage
    case errSecCodeSigningDevelopment
    case errSecResourceSignBadCertChainLength
    case errSecResourceSignBadExtKeyUsage
    case errSecTrustSettingDeny
    case errSecInvalidSubjectName
    case errSecUnknownQualifiedCertStatement
    case errSecMobileMeRequestQueued
    case errSecMobileMeRequestRedirected
    case errSecMobileMeServerError
    case errSecMobileMeServerNotAvailable
    case errSecMobileMeServerAlreadyExists
    case errSecMobileMeServerServiceErr
    case errSecMobileMeRequestAlreadyPending
    case errSecMobileMeNoRequestPending
    case errSecMobileMeCSRVerifyFailure
    case errSecMobileMeFailedConsistencyCheck
    case errSecNotInitialized
    case errSecInvalidHandleUsage
    case errSecPVCReferentNotFound
    case errSecFunctionIntegrityFail
    case errSecInternalError
    case errSecMemoryError
    case errSecInvalidData
    case errSecMDSError
    case errSecInvalidPointer
    case errSecSelfCheckFailed
    case errSecFunctionFailed
    case errSecModuleManifestVerifyFailed
    case errSecInvalidGUID
    case errSecInvalidHandle
    case errSecInvalidDBList
    case errSecInvalidPassthroughID
    case errSecInvalidNetworkAddress
    case errSecCRLAlreadySigned
    case errSecInvalidNumberOfFields
    case errSecVerificationFailure
    case errSecUnknownTag
    case errSecInvalidSignature
    case errSecInvalidName
    case errSecInvalidCertificateRef
    case errSecInvalidCertificateGroup
    case errSecTagNotFound
    case errSecInvalidQuery
    case errSecInvalidValue
    case errSecCallbackFailed
    case errSecACLDeleteFailed
    case errSecACLReplaceFailed
    case errSecACLAddFailed
    case errSecACLChangeFailed
    case errSecInvalidAccessCredentials
    case errSecInvalidRecord
    case errSecInvalidACL
    case errSecInvalidSampleValue
    case errSecIncompatibleVersion
    case errSecPrivilegeNotGranted
    case errSecInvalidScope
    case errSecPVCAlreadyConfigured
    case errSecInvalidPVC
    case errSecEMMLoadFailed
    case errSecEMMUnloadFailed
    case errSecAddinLoadFailed
    case errSecInvalidKeyRef
    case errSecInvalidKeyHierarchy
    case errSecAddinUnloadFailed
    case errSecLibraryReferenceNotFound
    case errSecInvalidAddinFunctionTable
    case errSecInvalidServiceMask
    case errSecModuleNotLoaded
    case errSecInvalidSubServiceID
    case errSecAttributeNotInContext
    case errSecModuleManagerInitializeFailed
    case errSecModuleManagerNotFound
    case errSecEventNotificationCallbackNotFound
    case errSecInputLengthError
    case errSecOutputLengthError
    case errSecPrivilegeNotSupported
    case errSecDeviceError
    case errSecAttachHandleBusy
    case errSecNotLoggedIn
    case errSecAlgorithmMismatch
    case errSecKeyUsageIncorrect
    case errSecKeyBlobTypeIncorrect
    case errSecKeyHeaderInconsistent
    case errSecUnsupportedKeyFormat
    case errSecUnsupportedKeySize
    case errSecInvalidKeyUsageMask
    case errSecUnsupportedKeyUsageMask
    case errSecInvalidKeyAttributeMask
    case errSecUnsupportedKeyAttributeMask
    case errSecInvalidKeyLabel
    case errSecUnsupportedKeyLabel
    case errSecInvalidKeyFormat
    case errSecUnsupportedVectorOfBuffers
    case errSecInvalidInputVector
    case errSecInvalidOutputVector
    case errSecInvalidContext
    case errSecInvalidAlgorithm
    case errSecInvalidAttributeKey
    case errSecMissingAttributeKey
    case errSecInvalidAttributeInitVector
    case errSecMissingAttributeInitVector
    case errSecInvalidAttributeSalt
    case errSecMissingAttributeSalt
    case errSecInvalidAttributePadding
    case errSecMissingAttributePadding
    case errSecInvalidAttributeRandom
    case errSecMissingAttributeRandom
    case errSecInvalidAttributeSeed
    case errSecMissingAttributeSeed
    case errSecInvalidAttributePassphrase
    case errSecMissingAttributePassphrase
    case errSecInvalidAttributeKeyLength
    case errSecMissingAttributeKeyLength
    case errSecInvalidAttributeBlockSize
    case errSecMissingAttributeBlockSize
    case errSecInvalidAttributeOutputSize
    case errSecMissingAttributeOutputSize
    case errSecInvalidAttributeRounds
    case errSecMissingAttributeRounds
    case errSecInvalidAlgorithmParms
    case errSecMissingAlgorithmParms
    case errSecInvalidAttributeLabel
    case errSecMissingAttributeLabel
    case errSecInvalidAttributeKeyType
    case errSecMissingAttributeKeyType
    case errSecInvalidAttributeMode
    case errSecMissingAttributeMode
    case errSecInvalidAttributeEffectiveBits
    case errSecMissingAttributeEffectiveBits
    case errSecInvalidAttributeStartDate
    case errSecMissingAttributeStartDate
    case errSecInvalidAttributeEndDate
    case errSecMissingAttributeEndDate
    case errSecInvalidAttributeVersion
    case errSecMissingAttributeVersion
    case errSecInvalidAttributePrime
    case errSecMissingAttributePrime
    case errSecInvalidAttributeBase
    case errSecMissingAttributeBase
    case errSecInvalidAttributeSubprime
    case errSecMissingAttributeSubprime
    case errSecInvalidAttributeIterationCount
    case errSecMissingAttributeIterationCount
    case errSecInvalidAttributeDLDBHandle
    case errSecMissingAttributeDLDBHandle
    case errSecInvalidAttributeAccessCredentials
    case errSecMissingAttributeAccessCredentials
    case errSecInvalidAttributePublicKeyFormat
    case errSecMissingAttributePublicKeyFormat
    case errSecInvalidAttributePrivateKeyFormat
    case errSecMissingAttributePrivateKeyFormat
    case errSecInvalidAttributeSymmetricKeyFormat
    case errSecMissingAttributeSymmetricKeyFormat
    case errSecInvalidAttributeWrappedKeyFormat
    case errSecMissingAttributeWrappedKeyFormat
    case errSecStagedOperationInProgress
    case errSecStagedOperationNotStarted
    case errSecVerifyFailed
    case errSecQuerySizeUnknown
    case errSecBlockSizeMismatch
    case errSecPublicKeyInconsistent
    case errSecDeviceVerifyFailed
    case errSecInvalidLoginName
    case errSecAlreadyLoggedIn
    case errSecInvalidDigestAlgorithm
    case errSecInvalidCRLGroup
    case errSecCertificateCannotOperate
    case errSecCertificateExpired
    case errSecCertificateNotValidYet
    case errSecCertificateRevoked
    case errSecCertificateSuspended
    case errSecInsufficientCredentials
    case errSecInvalidAction
    case errSecInvalidAuthority
    case errSecVerifyActionFailed
    case errSecInvalidCertAuthority
    case errSecInvalidCRLAuthority
    case errSecInvaldCRLAuthority
    case errSecInvalidCRLEncoding
    case errSecInvalidCRLType
    case errSecInvalidCRL
    case errSecInvalidFormType
    case errSecInvalidID
    case errSecInvalidIdentifier
    case errSecInvalidIndex
    case errSecInvalidPolicyIdentifiers
    case errSecInvalidTimeString
    case errSecInvalidReason
    case errSecInvalidRequestInputs
    case errSecInvalidResponseVector
    case errSecInvalidStopOnPolicy
    case errSecInvalidTuple
    case errSecMultipleValuesUnsupported
    case errSecNotTrusted
    case errSecNoDefaultAuthority
    case errSecRejectedForm
    case errSecRequestLost
    case errSecRequestRejected
    case errSecUnsupportedAddressType
    case errSecUnsupportedService
    case errSecInvalidTupleGroup
    case errSecInvalidBaseACLs
    case errSecInvalidTupleCredentials
    case errSecInvalidTupleCredendtials
    case errSecInvalidEncoding
    case errSecInvalidValidityPeriod
    case errSecInvalidRequestor
    case errSecRequestDescriptor
    case errSecInvalidBundleInfo
    case errSecInvalidCRLIndex
    case errSecNoFieldValues
    case errSecUnsupportedFieldFormat
    case errSecUnsupportedIndexInfo
    case errSecUnsupportedLocality
    case errSecUnsupportedNumAttributes
    case errSecUnsupportedNumIndexes
    case errSecUnsupportedNumRecordTypes
    case errSecFieldSpecifiedMultiple
    case errSecIncompatibleFieldFormat
    case errSecInvalidParsingModule
    case errSecDatabaseLocked
    case errSecDatastoreIsOpen
    case errSecMissingValue
    case errSecUnsupportedQueryLimits
    case errSecUnsupportedNumSelectionPreds
    case errSecUnsupportedOperator
    case errSecInvalidDBLocation
    case errSecInvalidAccessRequest
    case errSecInvalidIndexInfo
    case errSecInvalidNewOwner
    case errSecInvalidModifyMode
    case errSecMissingRequiredExtension
    case errSecExtendedKeyUsageNotCritical
    case errSecTimestampMissing
    case errSecTimestampInvalid
    case errSecTimestampNotTrusted
    case errSecTimestampServiceNotAvailable
    case errSecTimestampBadAlg
    case errSecTimestampBadRequest
    case errSecTimestampBadDataFormat
    case errSecTimestampTimeNotAvailable
    case errSecTimestampUnacceptedPolicy
    case errSecTimestampUnacceptedExtension
    case errSecTimestampAddInfoNotAvailable
    case errSecTimestampSystemFailure
    case errSecSigningTimeMissing
    case errSecTimestampRejection
    case errSecTimestampWaiting
    case errSecTimestampRevocationWarning
    case errSecTimestampRevocationNotification
    case errSecCertificatePolicyNotAllowed
    case errSecCertificateNameNotAllowed
    case errSecCertificateValidityPeriodTooLong
    case errSecCertificateIsCA
    case errSecCertificateDuplicateExtension
    
    case errSSLProtocol
    case errSSLNegotiation
    case errSSLFatalAlert
    case errSSLWouldBlock
    case errSSLSessionNotFound
    case errSSLClosedGraceful
    case errSSLClosedAbort
    case errSSLXCertChainInvalid
    case errSSLBadCert
    case errSSLCrypto
    case errSSLInternal
    case errSSLModuleAttach
    case errSSLUnknownRootCert
    case errSSLNoRootCert
    case errSSLCertExpired
    case errSSLCertNotYetValid
    case errSSLClosedNoNotify
    case errSSLBufferOverflow
    case errSSLBadCipherSuite
    
    //MARK: - fatal errors detected by peer
    case errSSLPeerUnexpectedMsg
    case errSSLPeerBadRecordMac
    case errSSLPeerDecryptionFail
    case errSSLPeerRecordOverflow
    case errSSLPeerDecompressFail
    case errSSLPeerHandshakeFail
    case errSSLPeerBadCert
    case errSSLPeerUnsupportedCert
    case errSSLPeerCertRevoked
    case errSSLPeerCertExpired
    case errSSLPeerCertUnknown
    case errSSLIllegalParam
    case errSSLPeerUnknownCA
    case errSSLPeerAccessDenied
    case errSSLPeerDecodeError
    case errSSLPeerDecryptError
    case errSSLPeerExportRestriction
    case errSSLPeerProtocolVersion
    case errSSLPeerInsufficientSecurity
    case errSSLPeerInternalError
    case errSSLPeerUserCancelled
    case errSSLPeerNoRenegotiation
    
    //MARK: - non-fatal result codes
    case errSSLPeerAuthCompleted
    case errSSLClientCertRequested
    
    //MARK: - more errors detected by us "
    case errSSLHostNameMismatch
    case errSSLConnectionRefused
    case errSSLDecryptionFail
    case errSSLBadRecordMac
    case errSSLRecordOverflow
    case errSSLBadConfiguration
    case errSSLUnexpectedRecord
    case errSSLWeakPeerEphemeralDHKey
    
    // MARK: - non-fatal result codes
    case errSSLClientHelloReceived
    
    // MARK: - fatal errors resulting from transport or networking errors
    case errSSLTransportReset
    case errSSLNetworkTimeout
    
    // MARK: - fatal errors resulting from software misconfiguration
    case errSSLConfigurationFailed
    
    // MARK: - additional errors
    case errSSLUnsupportedExtension
    case errSSLUnexpectedMessage
    case errSSLDecompressFail
    case errSSLHandshakeFail
    case errSSLDecodeError
    case errSSLInappropriateFallback
    case errSSLMissingExtension
    case errSSLBadCertificateStatusResponse
    case errSSLCertificateRequired
    case errSSLUnknownPSKIdentity
    case errSSLUnrecognizedName
    
    // MARK: -  ATS compliance violation errors "
    case errSSLATSViolation
    case errSSLATSMinimumVersionViolation
    case errSSLATSCiphersuiteViolation
    case errSSLATSMinimumKeySizeViolation
    case errSSLATSLeafCertificateHashAlgorithmViolation
    case errSSLATSCertificateHashAlgorithmViolation
    case errSSLATSCertificateTrustViolation
    
    // MARK: -  early data errors
    case errSSLEarlyDataRejected
    var errorDescription: String? {
        switch self {
        case .errSecUnimplemented:
            return  "Function or operation not implemented."
        case .errSecDiskFull:
            return " The disk is full. "
        case .errSecIO:
            return " I/O error. "
        case .errSecOpWr:
            return " File already open with write permission. "
        case .errSecParam:
            return " One or more parameters passed to a function were not valid. "
        case .errSecWrPerm:
            return " Write permissions error. "
        case .errSecAllocate:
            return " Failed to allocate memory. "
        case .errSecUserCanceled:
            return " User canceled the operation. "
        case .errSecBadReq:
            return " Bad parameter or invalid state for operation. "
        case .errSecInternalComponent:
            return "internal error "
        case .errSecCoreFoundationUnknown:
            return "unknown error"
        case .errSecMissingEntitlement:
            return " A required entitlement isn't present. "
        case .errSecRestrictedAPI:
            return " Client is restricted and is not permitted to perform this operation. "
        case .errSecNotAvailable:
            return " No keychain is available. You may need to restart your computer. "
        case .errSecReadOnly:
            return " This keychain cannot be modified. "
        case .errSecAuthFailed:
            return " A function was called without initializing CSSM. "
        case .errSecNoSuchKeychain:
            return " The specified keychain could not be found. "
        case .errSecInvalidKeychain:  return "The specified keychain is not a valid keychain file. "
        case .errSecDuplicateKeychain:  return "A keychain with the same name already exists. "
        case .errSecDuplicateCallback:  return "The specified callback function is already installed. "
        case .errSecInvalidCallback:  return "The specified callback function is not valid. "
        case .errSecDuplicateItem:  return "The specified item already exists in the keychain. "
        case .errSecItemNotFound:  return "The specified item could not be found in the keychain. "
        case .errSecBufferTooSmall:  return "There is not enough memory available to use the specified item. "
        case .errSecDataTooLarge:
            return "This item contains information which is too large or in a format that cannot be displayed. "
        case .errSecNoSuchAttr:  return "The specified attribute does not exist. "
        case .errSecInvalidItemRef:
            return "The specified item is no longer valid. It may have been deleted from the keychain. "
        case .errSecInvalidSearchRef:  return "Unable to search the current keychain. "
        case .errSecNoSuchClass:  return "The specified item does not appear to be a valid keychain item. "
        case .errSecNoDefaultKeychain:  return "A default keychain could not be found. "
        case .errSecInteractionNotAllowed:  return "User interaction is not allowed. "
        case .errSecReadOnlyAttr:  return "The specified attribute could not be modified. "
        case .errSecWrongSecVersion:
            return "This keychain was created by a different version of the system software and cannot be opened. "
        case .errSecKeySizeNotAllowed:
            return "This item specifies a key size which is too large or too small. "
        case .errSecNoStorageModule:
            return "A required component (data storage module) could not be loaded. You may need to restart your computer. "
        case .errSecNoCertificateModule:
            return "A required component (certificate module) could not be loaded. You may need to restart your computer. "
        case .errSecNoPolicyModule:
            return "A required component (policy module) could not be loaded. You may need to restart your computer. "
        case .errSecInteractionRequired:
            return "User interaction is required, but is currently not allowed. "
        case .errSecDataNotAvailable:  return "The contents of this item cannot be retrieved. "
        case .errSecDataNotModifiable:  return "The contents of this item cannot be modified. "
        case .errSecCreateChainFailed:
            return "One or more certificates required to validate this certificate cannot be found. "
        case .errSecInvalidPrefsDomain:
            return "The specified preferences domain is not valid. "
        case .errSecInDarkWake:
            return "In dark wake, no UI possible "
        case .errSecACLNotSimple:
            return "The specified access control list is not in standard (simple) form. "
        case .errSecPolicyNotFound:  return "The specified policy cannot be found. "
        case .errSecInvalidTrustSetting:  return "The specified trust setting is invalid. "
        case .errSecNoAccessForItem:  return "The specified item has no access control. "
        case .errSecInvalidOwnerEdit:  return "Invalid attempt to change the owner of this item. "
        case .errSecTrustNotAvailable:  return "No trust results are available. "
        case .errSecUnsupportedFormat:  return "Import/Export format unsupported. "
        case .errSecUnknownFormat:  return "Unknown format in import. "
        case .errSecKeyIsSensitive:  return "Key material must be wrapped for export. "
        case .errSecMultiplePrivKeys:  return "An attempt was made to import multiple private keys. "
        case .errSecPassphraseRequired:  return "Passphrase is required for import/export. "
        case .errSecInvalidPasswordRef:  return "The password reference was invalid. "
        case .errSecInvalidTrustSettings:  return "The Trust Settings Record was corrupted. "
        case .errSecNoTrustSettings:  return "No Trust Settings were found. "
        case .errSecPkcs12VerifyFailure:
            return "MAC verification failed during PKCS12 import (wrong password?) "
        case .errSecNotSigner:
            return "A certificate was not signed by its proposed parent. "
        case .errSecDecode:
            return "Unable to decode the provided data. "
        case .errSecServiceNotAvailable:  return "The required service is not available. "
        case .errSecInsufficientClientID:  return "The client ID is not correct. "
        case .errSecDeviceReset:  return "A device reset has occurred. "
        case .errSecDeviceFailed:  return "A device failure has occurred. "
        case .errSecAppleAddAppACLSubject:  return "Adding an application ACL subject failed. "
        case .errSecApplePublicKeyIncomplete:  return "The public key is incomplete. "
        case .errSecAppleSignatureMismatch:  return "A signature mismatch has occurred. "
        case .errSecAppleInvalidKeyStartDate:  return "The specified key has an invalid start date. "
        case .errSecAppleInvalidKeyEndDate:  return "The specified key has an invalid end date. "
        case .errSecConversionError:  return "A conversion error has occurred. "
        case .errSecAppleSSLv2Rollback:  return "A SSLv2 rollback error has occurred. "
        case .errSecQuotaExceeded:  return "The quota was exceeded. "
        case .errSecFileTooBig:  return "The file is too big. "
        case .errSecInvalidDatabaseBlob:  return "The specified database has an invalid blob. "
        case .errSecInvalidKeyBlob:  return "The specified database has an invalid key blob. "
        case .errSecIncompatibleDatabaseBlob:  return "The specified database has an incompatible blob. "
        case .errSecIncompatibleKeyBlob:  return "The specified database has an incompatible key blob. "
        case .errSecHostNameMismatch:  return "A host name mismatch has occurred. "
        case .errSecUnknownCriticalExtensionFlag:  return "There is an unknown critical extension flag. "
        case .errSecNoBasicConstraints:  return "No basic constraints were found. "
        case .errSecNoBasicConstraintsCA:  return "No basic CA constraints were found. "
        case .errSecInvalidAuthorityKeyID:  return "The authority key ID is not valid. "
        case .errSecInvalidSubjectKeyID:  return "The subject key ID is not valid. "
        case .errSecInvalidKeyUsageForPolicy:  return "The key usage is not valid for the specified policy. "
        case .errSecInvalidExtendedKeyUsage:  return "The extended key usage is not valid. "
        case .errSecInvalidIDLinkage:  return "The ID linkage is not valid. "
        case .errSecPathLengthConstraintExceeded:  return "The path length constraint was exceeded. "
        case .errSecInvalidRoot:  return "The root or anchor certificate is not valid. "
        case .errSecCRLExpired:  return "The CRL has expired. "
        case .errSecCRLNotValidYet:  return "The CRL is not yet valid. "
        case .errSecCRLNotFound:  return "The CRL was not found. "
        case .errSecCRLServerDown:  return "The CRL server is down. "
        case .errSecCRLBadURI:  return "The CRL has a bad Uniform Resource Identifier. "
        case .errSecUnknownCertExtension:  return "An unknown certificate extension was encountered. "
        case .errSecUnknownCRLExtension:  return "An unknown CRL extension was encountered. "
        case .errSecCRLNotTrusted:  return "The CRL is not trusted. "
        case .errSecCRLPolicyFailed:  return "The CRL policy failed. "
        case .errSecIDPFailure:  return "The issuing distribution point was not valid. "
        case .errSecSMIMEEmailAddressesNotFound:  return "An email address mismatch was encountered. "
        case .errSecSMIMEBadExtendedKeyUsage:
            return "The appropriate extended key usage for SMIME was not found. "
        case .errSecSMIMEBadKeyUsage:  return "The key usage is not compatible with SMIME. "
        case .errSecSMIMEKeyUsageNotCritical:  return "The key usage extension is not marked as critical. "
        case .errSecSMIMENoEmailAddress:  return "No email address was found in the certificate. "
        case .errSecSMIMESubjAltNameNotCritical:
            return "The subject alternative name extension is not marked as critical. "
        case .errSecSSLBadExtendedKeyUsage:
            return "The appropriate extended key usage for SSL was not found. "
        case .errSecOCSPBadResponse:  return "The OCSP response was incorrect or could not be parsed. "
        case .errSecOCSPBadRequest:  return "The OCSP request was incorrect or could not be parsed. "
        case .errSecOCSPUnavailable:  return "OCSP service is unavailable. "
        case .errSecOCSPStatusUnrecognized:  return "The OCSP server did not recognize this certificate. "
        case .errSecEndOfData:  return "An end-of-data was detected. "
        case .errSecIncompleteCertRevocationCheck:
            return "An incomplete certificate revocation check occurred. "
        case .errSecNetworkFailure:
            return "A network failure occurred. "
        case .errSecOCSPNotTrustedToAnchor:
            return "The OCSP response was not trusted to a root or anchor certificate. "
        case .errSecRecordModified:  return "The record was modified. "
        case .errSecOCSPSignatureError:  return "The OCSP response had an invalid signature. "
        case .errSecOCSPNoSigner:  return "The OCSP response had no signer. "
        case .errSecOCSPResponderMalformedReq:  return "The OCSP responder was given a malformed request. "
        case .errSecOCSPResponderInternalError:  return "The OCSP responder encountered an internal error. "
        case .errSecOCSPResponderTryLater:  return "The OCSP responder is busy, try again later. "
        case .errSecOCSPResponderSignatureRequired:  return "The OCSP responder requires a signature. "
        case .errSecOCSPResponderUnauthorized:
            return "The OCSP responder rejected this request as unauthorized. "
        case .errSecOCSPResponseNonceMismatch:  return "The OCSP response nonce did not match the request. "
        case .errSecCodeSigningBadCertChainLength:  return "Code signing encountered an incorrect certificate chain length. "
        case .errSecCodeSigningNoBasicConstraints:  return "Code signing found no basic constraints. "
        case .errSecCodeSigningBadPathLengthConstraint:  return "Code signing encountered an incorrect path length constraint. "
        case .errSecCodeSigningNoExtendedKeyUsage:  return "Code signing found no extended key usage. "
        case .errSecCodeSigningDevelopment:
            return "Code signing indicated use of a development-only certificate. "
        case .errSecResourceSignBadCertChainLength:
            return "Resource signing has encountered an incorrect certificate chain length. "
        case .errSecResourceSignBadExtKeyUsage:
            return "Resource signing has encountered an error in the extended key usage. "
        case .errSecTrustSettingDeny:  return "The trust setting for this policy was set to Deny. "
        case .errSecInvalidSubjectName:  return "An invalid certificate subject name was encountered. "
        case .errSecUnknownQualifiedCertStatement:
            return "An unknown qualified certificate statement was encountered. "
        case .errSecMobileMeRequestQueued: return ""
        case .errSecMobileMeRequestRedirected : return ""
        case .errSecMobileMeServerError: return ""
        case .errSecMobileMeServerNotAvailable: return ""
        case .errSecMobileMeServerAlreadyExists: return ""
        case .errSecMobileMeServerServiceErr: return ""
        case .errSecMobileMeRequestAlreadyPending: return ""
        case .errSecMobileMeNoRequestPending: return ""
        case .errSecMobileMeCSRVerifyFailure: return ""
        case .errSecMobileMeFailedConsistencyCheck: return ""
        case .errSecNotInitialized: return ""
        case .errSecInvalidHandleUsage: return ""
        case .errSecPVCReferentNotFound:
            return "A reference to the calling module was not found in the list of authorized callers. "
        case .errSecFunctionIntegrityFail:  return "A function address was not within the verified module. "
        case .errSecInternalError:  return "An internal error has occurred. "
        case .errSecMemoryError:  return "A memory error has occurred. "
        case .errSecInvalidData:  return "Invalid data was encountered. "
        case .errSecMDSError:  return "A Module Directory Service error has occurred. "
        case .errSecInvalidPointer:  return "An invalid pointer was encountered. "
        case .errSecSelfCheckFailed:  return "Self-check has failed. "
        case .errSecFunctionFailed:  return "A function has failed. "
        case .errSecModuleManifestVerifyFailed:
            return "A module manifest verification failure has occurred. "
        case .errSecInvalidGUID:  return "An invalid GUID was encountered. "
        case .errSecInvalidHandle:  return "An invalid handle was encountered. "
        case .errSecInvalidDBList:  return "An invalid DB list was encountered. "
        case .errSecInvalidPassthroughID:  return "An invalid passthrough ID was encountered. "
        case .errSecInvalidNetworkAddress:  return "An invalid network address was encountered. "
        case .errSecCRLAlreadySigned:  return "The certificate revocation list is already signed. "
        case .errSecInvalidNumberOfFields:  return "An invalid number of fields were encountered. "
        case .errSecVerificationFailure:  return "A verification failure occurred. "
        case .errSecUnknownTag:  return "An unknown tag was encountered. "
        case .errSecInvalidSignature:  return "An invalid signature was encountered. "
        case .errSecInvalidName:  return "An invalid name was encountered. "
        case .errSecInvalidCertificateRef:  return "An invalid certificate reference was encountered. "
        case .errSecInvalidCertificateGroup:  return "An invalid certificate group was encountered. "
        case .errSecTagNotFound:  return "The specified tag was not found. "
        case .errSecInvalidQuery:  return "The specified query was not valid. "
        case .errSecInvalidValue:  return "An invalid value was detected. "
        case .errSecCallbackFailed:  return "A callback has failed. "
        case .errSecACLDeleteFailed:  return "An ACL delete operation has failed. "
        case .errSecACLReplaceFailed:  return "An ACL replace operation has failed. "
        case .errSecACLAddFailed:  return "An ACL add operation has failed. "
        case .errSecACLChangeFailed:  return "An ACL change operation has failed. "
        case .errSecInvalidAccessCredentials:  return "Invalid access credentials were encountered. "
        case .errSecInvalidRecord:  return "An invalid record was encountered. "
        case .errSecInvalidACL:  return "An invalid ACL was encountered. "
        case .errSecInvalidSampleValue:  return "An invalid sample value was encountered. "
        case .errSecIncompatibleVersion:  return "An incompatible version was encountered. "
        case .errSecPrivilegeNotGranted:  return "The privilege was not granted. "
        case .errSecInvalidScope:  return "An invalid scope was encountered. "
        case .errSecPVCAlreadyConfigured:  return "The PVC is already configured. "
        case .errSecInvalidPVC:  return "An invalid PVC was encountered. "
        case .errSecEMMLoadFailed:  return "The EMM load has failed. "
        case .errSecEMMUnloadFailed:  return "The EMM unload has failed. "
        case .errSecAddinLoadFailed:  return "The add-in load operation has failed. "
        case .errSecInvalidKeyRef:  return "An invalid key was encountered. "
        case .errSecInvalidKeyHierarchy:  return "An invalid key hierarchy was encountered. "
        case .errSecAddinUnloadFailed:  return "The add-in unload operation has failed. "
        case .errSecLibraryReferenceNotFound:  return "A library reference was not found. "
        case .errSecInvalidAddinFunctionTable:  return "An invalid add-in function table was encountered. "
        case .errSecInvalidServiceMask:  return "An invalid service mask was encountered. "
        case .errSecModuleNotLoaded:  return "A module was not loaded. "
        case .errSecInvalidSubServiceID:  return "An invalid subservice ID was encountered. "
        case .errSecAttributeNotInContext:  return "An attribute was not in the context. "
        case .errSecModuleManagerInitializeFailed:  return "A module failed to initialize. "
        case .errSecModuleManagerNotFound:  return "A module was not found. "
        case .errSecEventNotificationCallbackNotFound:
            return "An event notification callback was not found. "
        case .errSecInputLengthError:  return "An input length error was encountered. "
        case .errSecOutputLengthError:  return "An output length error was encountered. "
        case .errSecPrivilegeNotSupported:  return "The privilege is not supported. "
        case .errSecDeviceError:  return "A device error was encountered. "
        case .errSecAttachHandleBusy:  return "The CSP handle was busy. "
        case .errSecNotLoggedIn:  return "You are not logged in. "
        case .errSecAlgorithmMismatch:  return "An algorithm mismatch was encountered. "
        case .errSecKeyUsageIncorrect:  return "The key usage is incorrect. "
        case .errSecKeyBlobTypeIncorrect:  return "The key blob type is incorrect. "
        case .errSecKeyHeaderInconsistent:  return "The key header is inconsistent. "
        case .errSecUnsupportedKeyFormat:  return "The key header format is not supported. "
        case .errSecUnsupportedKeySize:  return "The key size is not supported. "
        case .errSecInvalidKeyUsageMask:  return "The key usage mask is not valid. "
        case .errSecUnsupportedKeyUsageMask:  return "The key usage mask is not supported. "
        case .errSecInvalidKeyAttributeMask:  return "The key attribute mask is not valid. "
        case .errSecUnsupportedKeyAttributeMask:  return "The key attribute mask is not supported. "
        case .errSecInvalidKeyLabel:  return "The key label is not valid. "
        case .errSecUnsupportedKeyLabel:  return "The key label is not supported. "
        case .errSecInvalidKeyFormat:  return "The key format is not valid. "
        case .errSecUnsupportedVectorOfBuffers:  return "The vector of buffers is not supported. "
        case .errSecInvalidInputVector:  return "The input vector is not valid. "
        case .errSecInvalidOutputVector:  return "The output vector is not valid. "
        case .errSecInvalidContext:  return "An invalid context was encountered. "
        case .errSecInvalidAlgorithm:  return "An invalid algorithm was encountered. "
        case .errSecInvalidAttributeKey:  return "A key attribute was not valid. "
        case .errSecMissingAttributeKey:  return "A key attribute was missing. "
        case .errSecInvalidAttributeInitVector:  return "An init vector attribute was not valid. "
        case .errSecMissingAttributeInitVector:  return "An init vector attribute was missing. "
        case .errSecInvalidAttributeSalt:  return "A salt attribute was not valid. "
        case .errSecMissingAttributeSalt:  return "A salt attribute was missing. "
        case .errSecInvalidAttributePadding:  return "A padding attribute was not valid. "
        case .errSecMissingAttributePadding:  return "A padding attribute was missing. "
        case .errSecInvalidAttributeRandom:  return "A random number attribute was not valid. "
        case .errSecMissingAttributeRandom:  return "A random number attribute was missing. "
        case .errSecInvalidAttributeSeed:  return "A seed attribute was not valid. "
        case .errSecMissingAttributeSeed:  return "A seed attribute was missing. "
        case .errSecInvalidAttributePassphrase:  return "A passphrase attribute was not valid. "
        case .errSecMissingAttributePassphrase:  return "A passphrase attribute was missing. "
        case .errSecInvalidAttributeKeyLength:  return "A key length attribute was not valid. "
        case .errSecMissingAttributeKeyLength:  return "A key length attribute was missing. "
        case .errSecInvalidAttributeBlockSize:  return "A block size attribute was not valid. "
        case .errSecMissingAttributeBlockSize:  return "A block size attribute was missing. "
        case .errSecInvalidAttributeOutputSize:  return "An output size attribute was not valid. "
        case .errSecMissingAttributeOutputSize:  return "An output size attribute was missing. "
        case .errSecInvalidAttributeRounds:  return "The number of rounds attribute was not valid. "
        case .errSecMissingAttributeRounds:  return "The number of rounds attribute was missing. "
        case .errSecInvalidAlgorithmParms:  return "An algorithm parameters attribute was not valid. "
        case .errSecMissingAlgorithmParms:  return "An algorithm parameters attribute was missing. "
        case .errSecInvalidAttributeLabel:  return "A label attribute was not valid. "
        case .errSecMissingAttributeLabel:  return "A label attribute was missing. "
        case .errSecInvalidAttributeKeyType:  return "A key type attribute was not valid. "
        case .errSecMissingAttributeKeyType:  return "A key type attribute was missing. "
        case .errSecInvalidAttributeMode:  return "A mode attribute was not valid. "
        case .errSecMissingAttributeMode:  return "A mode attribute was missing. "
        case .errSecInvalidAttributeEffectiveBits:  return "An effective bits attribute was not valid. "
        case .errSecMissingAttributeEffectiveBits:  return "An effective bits attribute was missing. "
        case .errSecInvalidAttributeStartDate:  return "A start date attribute was not valid. "
        case .errSecMissingAttributeStartDate:  return "A start date attribute was missing. "
        case .errSecInvalidAttributeEndDate:  return "An end date attribute was not valid. "
        case .errSecMissingAttributeEndDate:  return "An end date attribute was missing. "
        case .errSecInvalidAttributeVersion:  return "A version attribute was not valid. "
        case .errSecMissingAttributeVersion:  return "A version attribute was missing. "
        case .errSecInvalidAttributePrime:  return "A prime attribute was not valid. "
        case .errSecMissingAttributePrime:  return "A prime attribute was missing. "
        case .errSecInvalidAttributeBase:  return "A base attribute was not valid. "
        case .errSecMissingAttributeBase:  return "A base attribute was missing. "
        case .errSecInvalidAttributeSubprime:  return "A subprime attribute was not valid. "
        case .errSecMissingAttributeSubprime:  return "A subprime attribute was missing. "
        case .errSecInvalidAttributeIterationCount:  return "An iteration count attribute was not valid. "
        case .errSecMissingAttributeIterationCount:  return "An iteration count attribute was missing. "
        case .errSecInvalidAttributeDLDBHandle:  return "A database handle attribute was not valid. "
        case .errSecMissingAttributeDLDBHandle:  return "A database handle attribute was missing. "
        case .errSecInvalidAttributeAccessCredentials:
            return "An access credentials attribute was not valid. "
        case .errSecMissingAttributeAccessCredentials:  return "An access credentials attribute was missing. "
        case .errSecInvalidAttributePublicKeyFormat:  return "A public key format attribute was not valid. "
        case .errSecMissingAttributePublicKeyFormat:  return "A public key format attribute was missing. "
        case .errSecInvalidAttributePrivateKeyFormat:  return "A private key format attribute was not valid. "
        case .errSecMissingAttributePrivateKeyFormat:  return "A private key format attribute was missing. "
        case .errSecInvalidAttributeSymmetricKeyFormat:
            return "A symmetric key format attribute was not valid. "
        case .errSecMissingAttributeSymmetricKeyFormat:
            return "A symmetric key format attribute was missing. "
        case .errSecInvalidAttributeWrappedKeyFormat:  return "A wrapped key format attribute was not valid. "
        case .errSecMissingAttributeWrappedKeyFormat:  return "A wrapped key format attribute was missing. "
        case .errSecStagedOperationInProgress:  return "A staged operation is in progress. "
        case .errSecStagedOperationNotStarted:  return "A staged operation was not started. "
        case .errSecVerifyFailed:  return "A cryptographic verification failure has occurred. "
        case .errSecQuerySizeUnknown:  return "The query size is unknown. "
        case .errSecBlockSizeMismatch:  return "A block size mismatch occurred. "
        case .errSecPublicKeyInconsistent:  return "The public key was inconsistent. "
        case .errSecDeviceVerifyFailed:  return "A device verification failure has occurred. "
        case .errSecInvalidLoginName:  return "An invalid login name was detected. "
        case .errSecAlreadyLoggedIn:  return "The user is already logged in. "
        case .errSecInvalidDigestAlgorithm:  return "An invalid digest algorithm was detected. "
        case .errSecInvalidCRLGroup:  return "An invalid CRL group was detected. "
        case .errSecCertificateCannotOperate:  return "The certificate cannot operate. "
        case .errSecCertificateExpired:  return "An expired certificate was detected. "
        case .errSecCertificateNotValidYet:  return "The certificate is not yet valid. "
        case .errSecCertificateRevoked:  return "The certificate was revoked. "
        case .errSecCertificateSuspended:  return "The certificate was suspended. "
        case .errSecInsufficientCredentials:  return "Insufficient credentials were detected. "
        case .errSecInvalidAction:  return "The action was not valid. "
        case .errSecInvalidAuthority:  return "The authority was not valid. "
        case .errSecVerifyActionFailed:  return "A verify action has failed. "
        case .errSecInvalidCertAuthority:  return "The certificate authority was not valid. "
        case .errSecInvalidCRLAuthority:  return "The CRL authority was not valid. "
        case .errSecInvaldCRLAuthority: return "The CRL authority was not valid. "
        case .errSecInvalidCRLEncoding:  return "The CRL encoding was not valid. "
        case .errSecInvalidCRLType:  return "The CRL type was not valid. "
        case .errSecInvalidCRL:  return "The CRL was not valid. "
        case .errSecInvalidFormType:  return "The form type was not valid. "
        case .errSecInvalidID:  return "The ID was not valid. "
        case .errSecInvalidIdentifier:  return "The identifier was not valid. "
        case .errSecInvalidIndex:  return "The index was not valid. "
        case .errSecInvalidPolicyIdentifiers:  return "The policy identifiers are not valid. "
        case .errSecInvalidTimeString:  return "The time specified was not valid. "
        case .errSecInvalidReason:  return "The trust policy reason was not valid. "
        case .errSecInvalidRequestInputs:  return "The request inputs are not valid. "
        case .errSecInvalidResponseVector:  return "The response vector was not valid. "
        case .errSecInvalidStopOnPolicy:  return "The stop-on policy was not valid. "
        case .errSecInvalidTuple:  return "The tuple was not valid. "
        case .errSecMultipleValuesUnsupported:  return "Multiple values are not supported. "
        case .errSecNotTrusted:  return "The certificate was not trusted. "
        case .errSecNoDefaultAuthority:  return "No default authority was detected. "
        case .errSecRejectedForm:  return "The trust policy had a rejected form. "
        case .errSecRequestLost:  return "The request was lost. "
        case .errSecRequestRejected:  return "The request was rejected. "
        case .errSecUnsupportedAddressType:  return "The address type is not supported. "
        case .errSecUnsupportedService:  return "The service is not supported. "
        case .errSecInvalidTupleGroup:  return "The tuple group was not valid. "
        case .errSecInvalidBaseACLs:  return "The base ACLs are not valid. "
        case .errSecInvalidTupleCredentials:  return "The tuple credentials are not valid. "
        case .errSecInvalidTupleCredendtials:   return "The tuple credentials are not valid. "
        case .errSecInvalidEncoding:  return "The encoding was not valid. "
        case .errSecInvalidValidityPeriod:  return "The validity period was not valid. "
        case .errSecInvalidRequestor:  return "The requestor was not valid. "
        case .errSecRequestDescriptor:  return "The request descriptor was not valid. "
        case .errSecInvalidBundleInfo:  return "The bundle information was not valid. "
        case .errSecInvalidCRLIndex:  return "The CRL index was not valid. "
        case .errSecNoFieldValues:  return "No field values were detected. "
        case .errSecUnsupportedFieldFormat:  return "The field format is not supported. "
        case .errSecUnsupportedIndexInfo:  return "The index information is not supported. "
        case .errSecUnsupportedLocality:  return "The locality is not supported. "
        case .errSecUnsupportedNumAttributes:  return "The number of attributes is not supported. "
        case .errSecUnsupportedNumIndexes:  return "The number of indexes is not supported. "
        case .errSecUnsupportedNumRecordTypes:  return "The number of record types is not supported. "
        case .errSecFieldSpecifiedMultiple:  return "Too many fields were specified. "
        case .errSecIncompatibleFieldFormat:  return "The field format was incompatible. "
        case .errSecInvalidParsingModule:  return "The parsing module was not valid. "
        case .errSecDatabaseLocked:  return "The database is locked. "
        case .errSecDatastoreIsOpen:  return "The data store is open. "
        case .errSecMissingValue:  return "A missing value was detected. "
        case .errSecUnsupportedQueryLimits:  return "The query limits are not supported. "
        case .errSecUnsupportedNumSelectionPreds:
            return "The number of selection predicates is not supported. "
        case .errSecUnsupportedOperator:  return "The operator is not supported. "
        case .errSecInvalidDBLocation:  return "The database location is not valid. "
        case .errSecInvalidAccessRequest:  return "The access request is not valid. "
        case .errSecInvalidIndexInfo:  return "The index information is not valid. "
        case .errSecInvalidNewOwner:  return "The new owner is not valid. "
        case .errSecInvalidModifyMode:  return "The modify mode is not valid. "
        case .errSecMissingRequiredExtension:  return "A required certificate extension is missing. "
        case .errSecExtendedKeyUsageNotCritical:  return "The extended key usage extension was not marked critical. "
        case .errSecTimestampMissing:  return "A timestamp was expected but was not found. "
        case .errSecTimestampInvalid:  return "The timestamp was not valid. "
        case .errSecTimestampNotTrusted:  return "The timestamp was not trusted. "
        case .errSecTimestampServiceNotAvailable:  return "The timestamp service is not available. "
        case .errSecTimestampBadAlg:  return "An unrecognized or unsupported Algorithm Identifier in timestamp. "
        case .errSecTimestampBadRequest:  return "The timestamp transaction is not permitted or supported. "
        case .errSecTimestampBadDataFormat:  return "The timestamp data submitted has the wrong format. "
        case .errSecTimestampTimeNotAvailable:  return "The time source for the Timestamp Authority is not available. "
        case .errSecTimestampUnacceptedPolicy:  return "The requested policy is not supported by the Timestamp Authority. "
        case .errSecTimestampUnacceptedExtension:  return "The requested extension is not supported by the Timestamp Authority. "
        case .errSecTimestampAddInfoNotAvailable:
            return "The additional information requested is not available. "
        case .errSecTimestampSystemFailure:
            return "The timestamp request cannot be handled due to system failure. "
        case .errSecSigningTimeMissing:  return "A signing time was expected but was not found. "
        case .errSecTimestampRejection:  return "A timestamp transaction was rejected. "
        case .errSecTimestampWaiting:  return "A timestamp transaction is waiting. "
        case .errSecTimestampRevocationWarning:
            return "A timestamp authority revocation warning was issued. "
        case .errSecTimestampRevocationNotification:
            return "A timestamp authority revocation notification was issued. "
        case .errSecCertificatePolicyNotAllowed:
            return "The requested policy is not allowed for this certificate. "
        case .errSecCertificateNameNotAllowed:
            return "The requested name is not allowed for this certificate. "
        case .errSecCertificateValidityPeriodTooLong:
            return "The validity period in the certificate exceeds the maximum allowed. "
        case .errSecCertificateIsCA:
            return "The verified certificate is a CA rather than an end-entity "
        case .errSecCertificateDuplicateExtension:
            return "The certificate contains multiple extensions with the same extension ID. "
        case .errSSLProtocol:  return "SSL protocol error "
        case .errSSLNegotiation:  return "Cipher Suite negotiation failure "
        case .errSSLFatalAlert:  return "Fatal alert "
        case .errSSLWouldBlock:  return "I/O would block (not fatal) "
        case .errSSLSessionNotFound:  return "attempt to restore an unknown session "
        case .errSSLClosedGraceful:  return "connection closed gracefully "
        case .errSSLClosedAbort:  return "connection closed via error "
        case .errSSLXCertChainInvalid:  return "invalid certificate chain "
        case .errSSLBadCert:  return "bad certificate format "
        case .errSSLCrypto:  return "underlying cryptographic error "
        case .errSSLInternal:  return "Internal error "
        case .errSSLModuleAttach:  return "module attach failure "
        case .errSSLUnknownRootCert:  return "valid cert chain, untrusted root "
        case .errSSLNoRootCert:  return "cert chain not verified by root "
        case .errSSLCertExpired:  return "chain had an expired cert "
        case .errSSLCertNotYetValid:  return "chain had a cert not yet valid "
        case .errSSLClosedNoNotify:  return "server closed session with no notification "
        case .errSSLBufferOverflow:  return "insufficient buffer provided "
        case .errSSLBadCipherSuite:  return "bad SSLCipherSuite "
            // MARK: -  return "fatal errors detected by peer "
        case .errSSLPeerUnexpectedMsg:  return "unexpected message received "
        case .errSSLPeerBadRecordMac:  return "bad MAC "
        case .errSSLPeerDecryptionFail:  return "decryption failed "
        case .errSSLPeerRecordOverflow:  return "record overflow "
        case .errSSLPeerDecompressFail:  return "decompression failure "
        case .errSSLPeerHandshakeFail:  return "handshake failure "
        case .errSSLPeerBadCert:  return "misc. bad certificate "
        case .errSSLPeerUnsupportedCert:  return "bad unsupported cert format "
        case .errSSLPeerCertRevoked:  return "certificate revoked "
        case .errSSLPeerCertExpired:  return "certificate expired "
        case .errSSLPeerCertUnknown:  return "unknown certificate "
        case .errSSLIllegalParam:  return "illegal parameter "
        case .errSSLPeerUnknownCA:  return "unknown Cert Authority "
        case .errSSLPeerAccessDenied:  return "access denied "
        case .errSSLPeerDecodeError:  return "decoding error "
        case .errSSLPeerDecryptError:  return "decryption error "
        case .errSSLPeerExportRestriction:  return "export restriction "
        case .errSSLPeerProtocolVersion:  return "bad protocol version "
        case .errSSLPeerInsufficientSecurity:  return "insufficient security "
        case .errSSLPeerInternalError:  return "internal error "
        case .errSSLPeerUserCancelled:  return "user canceled "
        case .errSSLPeerNoRenegotiation:  return "no renegotiation allowed "
            // MARK: -  return "non-fatal result codes "
        case .errSSLPeerAuthCompleted:
            return "peer cert is valid, or was ignored if verification disabled "
        case .errSSLClientCertRequested:
            return "server has requested a client cert "
            // MARK: -  return "more errors detected by us "
        case .errSSLHostNameMismatch:  return "peer host name mismatch "
        case .errSSLConnectionRefused:  return "peer dropped connection before responding "
        case .errSSLDecryptionFail:  return "decryption failure "
        case .errSSLBadRecordMac:  return "bad MAC "
        case .errSSLRecordOverflow:  return "record overflow "
        case .errSSLBadConfiguration:  return "configuration error "
        case .errSSLUnexpectedRecord:  return "unexpected (skipped) record in DTLS "
        case .errSSLWeakPeerEphemeralDHKey:  return "weak ephemeral dh key  "
            
            // MARK: -  return "non-fatal result codes "
        case .errSSLClientHelloReceived:  return "SNI "
            
            // MARK: -  return "fatal errors resulting from transport or networking errors "
        case .errSSLTransportReset:  return "transport (socket) shutdown, e.g., TCP RST or FIN. "
        case .errSSLNetworkTimeout:  return "network timeout triggered "
            // MARK: -  return "fatal errors resulting from software misconfiguration "
        case .errSSLConfigurationFailed:  return "TLS configuration failed "
            // MARK: -  return "additional errors "
        case .errSSLUnsupportedExtension:  return "unsupported TLS extension "
        case .errSSLUnexpectedMessage:  return "peer rejected unexpected message "
        case .errSSLDecompressFail:  return "decompression failed "
        case .errSSLHandshakeFail:  return "handshake failed "
        case .errSSLDecodeError:  return "decode failed "
        case .errSSLInappropriateFallback:  return "inappropriate fallback "
        case .errSSLMissingExtension:  return "missing extension "
        case .errSSLBadCertificateStatusResponse:  return "bad OCSP response "
        case .errSSLCertificateRequired:  return "certificate required "
        case .errSSLUnknownPSKIdentity:  return "unknown PSK identity "
        case .errSSLUnrecognizedName:  return "unknown or unrecognized name "
            // MARK: -  return "ATS compliance violation errors "
        case .errSSLATSViolation:  return "ATS violation "
        case .errSSLATSMinimumVersionViolation:
            return "ATS violation: minimum protocol version is not ATS compliant "
        case .errSSLATSCiphersuiteViolation:
            return "ATS violation: selected ciphersuite is not ATS compliant "
        case .errSSLATSMinimumKeySizeViolation:
            return "ATS violation: peer key size is not ATS compliant "
        case .errSSLATSLeafCertificateHashAlgorithmViolation:
            return "ATS violation: peer leaf certificate hash algorithm is not ATS compliant "
        case .errSSLATSCertificateHashAlgorithmViolation:
            return "ATS violation: peer certificate hash algorithm is not ATS compliant "
        case .errSSLATSCertificateTrustViolation:
            return "ATS violation: peer certificate is not issued by trusted peer "
            //  MARK: -  return "early data errors "
        case .errSSLEarlyDataRejected:  return "Early application data rejected by peer "
        }
    }
}
