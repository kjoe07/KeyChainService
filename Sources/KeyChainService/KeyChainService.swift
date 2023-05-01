import Foundation
import Security

let kSecClassValue = NSString(format: kSecClass)
let kSecAttrAccountValue = NSString(format: kSecAttrAccount)
let kSecValueDataValue = NSString(format: kSecValueData)
let kSecClassGenericPasswordValue = NSString(format: kSecClassGenericPassword)
let kSecAttrServiceValue = NSString(format: kSecAttrService)
let kSecMatchLimitValue = NSString(format: kSecMatchLimit)
let kSecReturnDataValue = NSString(format: kSecReturnData)
let kSecMatchLimitOneValue = NSString(format: kSecMatchLimitOne)

public class KeychainService: NSObject {

    static public func updatePassword(service: String, account: String, data: String) throws {
        if let dataFromString: Data = data.data(using: String.Encoding.utf8, allowLossyConversion: false) {

            // Instantiate a new default keychain query
            let keys = [kSecClassValue, kSecAttrServiceValue, kSecAttrAccountValue]
            let keychainQuery: NSMutableDictionary = NSMutableDictionary(objects: [kSecClassGenericPasswordValue, service, account], forKeys: keys)

            let status = SecItemUpdate(keychainQuery as CFDictionary, [kSecValueDataValue: dataFromString] as CFDictionary)

            if status != errSecSuccess {
                throw KeyChainError(rawValue: status) ?? ConversionError.unknownError
            }
        }
    }
    
    /// remove a value from keychain
    /// - Parameters:
    ///   - service: name of the service bundle name
    ///   - account: the name of the value to remove 
    static public func removePassword(service: String,
                                      account: String) throws {
        let keys = [kSecClassValue, kSecAttrServiceValue, kSecAttrAccountValue, kSecReturnDataValue]
        // Instantiate a new default keychain query
        let keychainQuery: NSMutableDictionary = NSMutableDictionary(objects: [kSecClassGenericPasswordValue, service, account, kCFBooleanTrue ?? true], forKeys: keys)

        // Delete any existing items
        let status = SecItemDelete(keychainQuery as CFDictionary)
        if status != errSecSuccess {
            throw KeyChainError(rawValue: status) ?? ConversionError.unknownError
        }

    }
    
    /// save a password in string format into the keychain
    /// - Parameters:
    ///   - service: name of the service, use bundle id
    ///   - account: the nam of the data to save like token, password or username
    ///   - data: string value of the data to store
    static public func savePassword(service: String,
                                    account: String,
                                    data: String) throws {
        if let dataFromString = data.data(using: String.Encoding.utf8, allowLossyConversion: false) {
            let keys = [kSecClassValue, kSecAttrServiceValue, kSecAttrAccountValue, kSecValueDataValue]
            // Instantiate a new default keychain query
            let keychainQuery: NSMutableDictionary = NSMutableDictionary(objects: [kSecClassGenericPasswordValue, service, account, dataFromString], forKeys: keys)

            // Add the new keychain item
            let status = SecItemAdd(keychainQuery as CFDictionary, nil)

            if status != errSecSuccess {    // Always check the status
                throw KeyChainError(rawValue: status) ?? ConversionError.unknownError
            }
        }
    }
    
    /// load a string from keychain
    /// - Parameters:
    ///   - service: the name of the service use the bundle name to avoid colition with another app using the same account name
    ///   - account: the name of the field to read from keychain
    /// - Returns: an string from keychain
    static public func loadPassword(service: String, account: String) throws -> String {
        // Instantiate a new default keychain query
        // Tell the query to return a result
        // Limit our results to one item
        let keys = [kSecClassValue, kSecAttrServiceValue, kSecAttrAccountValue, kSecReturnDataValue, kSecMatchLimitValue]
        let keychainQuery: NSMutableDictionary = NSMutableDictionary(objects: [kSecClassGenericPasswordValue, service, account, kCFBooleanTrue ?? true, kSecMatchLimitOneValue], forKeys: keys)

        var dataTypeRef: AnyObject?

        // Search for the keychain items
        let status: OSStatus = SecItemCopyMatching(keychainQuery, &dataTypeRef)

        if status == errSecSuccess {
            if let retrievedData = dataTypeRef as? Data, let contentsOfKeychain = String(data: retrievedData, encoding: String.Encoding.utf8) {
                return contentsOfKeychain
            } else {
                throw ConversionError.conversionFailed
            }
        } else {
            throw  KeyChainError(rawValue: status) ?? ConversionError.unknownError
        }
    }
}
public enum ConversionError: LocalizedError {
    case conversionFailed
    case unknownError
}
