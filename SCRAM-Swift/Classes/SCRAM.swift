//
//  SCRAM.swift
//  SCRAM-Swift
//
//  Created by Alin Radut on 18/06/2020.
//

import Foundation
import CommonCrypto

func trace(_ key: String, _ value: Any) {
    guard SCRAM.debug else {
        return
    }
    print("\(key): \(value)")
}

/// Hash algorithm to use with SCRAM.
public enum HashAlgorithm {
    
    case sha1
    case sha256
    case sha512
    
    public var hmac: CCHmacAlgorithm {
        switch self {
        case .sha1:
            return CCHmacAlgorithm(kCCHmacAlgSHA1)
        case .sha256:
            return CCHmacAlgorithm(kCCHmacAlgSHA256)
        case .sha512:
            return CCHmacAlgorithm(kCCHmacAlgSHA512)
        }
    }
    
    public var algo: Int {
        switch self {
        case .sha1:
            return kCCPRFHmacAlgSHA1
        case .sha256:
            return kCCPRFHmacAlgSHA256
        case .sha512:
            return kCCPRFHmacAlgSHA512
        }
    }
    
    public var digestLength: Int32 {
        switch self {
        case .sha1:
            return CC_SHA1_DIGEST_LENGTH
        case .sha256:
            return CC_SHA256_DIGEST_LENGTH
        case .sha512:
            return CC_SHA512_DIGEST_LENGTH
        }
    }
    
    public var prf: CCPseudoRandomAlgorithm {
        switch self {
        case .sha1:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        case .sha256:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .sha512:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }
    }
}

enum SCRAMError: Error {
    case invalidInput(String)
    case invalidState
}

open class SCRAM {
    
    public struct InitialClientMessage {
        
        /// Plaintext message
        public var message: String {
            return [
                SCRAM.initialMessageHeader,
                bare
            ].joined(separator: ",")
        }
        
        var bare: String {
            return [
                "n=\(username)",
                "r=\(nonce)"
            ].joined(separator: ",")
        }
        
        /// Base64 encoded `message`. This shoul be sent to the server.
        public var base64EncodedMessage: String {
            return message.data(using: .utf8)!.base64EncodedString()
        }
        
        var username: String
        var password: String
        var nonce: String
        var algorithm: HashAlgorithm
    }
    
    public struct InitialServerMessage {
        
        var serverNonce: String
        var salt: Data
        var iterations: Int
        
        var challenge: String
        
        init(challenge: String, initialMessage: InitialClientMessage) throws {
            let components = challenge.components(separatedBy: ",")
            
            guard components.count == 3 else {
                throw SCRAMError.invalidInput("Incorrect challenge format")
            }
            
            guard components[0].count > 2, components[0].hasPrefix("r=") else {
                throw SCRAMError.invalidInput("Invalid server nonce")
            }
            
            guard components[1].count > 2, components[1].hasPrefix("s="),
                let salt = Data(base64Encoded: components[1].substring(from: 2)) else {
                throw SCRAMError.invalidInput("Invalid salt")
            }
            
            guard components[2].count > 2, components[2].hasPrefix("i="),
                let iterations = Int(components[2].substring(from: 2)) else {
                throw SCRAMError.invalidInput("Invalid number of iterations")
            }
            
            self.serverNonce = components[0].substring(from: 2)
            self.salt = salt
            self.iterations = iterations
            
            trace("server nonce", serverNonce)
            trace("salt", salt.toHex())
            trace("iterations", iterations)
            
            self.challenge = challenge
        }
    }
    
    public struct FinalClientMessage {
        
        public var message: String!
        
        /// Base64 encoded `message`. This shoul be sent to the server.
        public var base64EncodedMessage: String {
            return message.data(using: .utf8)!.base64EncodedString()
        }
        
        var serverNonce: String
        var serverSignature: Data
                
        init(serverChallenge: InitialServerMessage, initialMessage: InitialClientMessage) {

            self.serverNonce = serverChallenge.serverNonce

            let passwordData = initialMessage.password.data(using: .utf8)!
            let saltData = serverChallenge.salt
            let hashAlgo = initialMessage.algorithm
            let saltedPassword: Data = passwordData.derive(salt: saltData, algorithm: hashAlgo, iterations: serverChallenge.iterations)
            trace("salted password", saltedPassword.toHex())

            let clientKeyData = "Client Key".hmac(key: saltedPassword, algorithm: hashAlgo)
            let clientKey = clientKeyData
            trace("client key", clientKey.toHex())
            
            let storedKey = clientKeyData.hash(algorithm: hashAlgo)
            trace("stored key", storedKey.toHex())

            let bare: String = SCRAM.finalMessageHeader + ",r=" + serverNonce
            trace("final client message bare", bare)

            let authMessage = [initialMessage.bare, serverChallenge.challenge, bare].joined(separator: ",")
            trace("auth message", authMessage)

            let clientSignature = authMessage.hmac(key: storedKey, algorithm: hashAlgo)
            trace("client signature", clientSignature.toHex())

            let clientProof = clientKey.xored(with: clientSignature)
            trace("client proof", clientProof.toHex())

            let serverKey = "Server Key".hmac(key: saltedPassword, algorithm: hashAlgo)
            trace("server key", serverKey.toHex())

            serverSignature = authMessage.hmac(key: serverKey, algorithm: hashAlgo)
            trace("server signature", serverSignature.toHex())

            let clientFinalMessage = bare + ",p=" + clientProof.base64EncodedString()
            trace("client final message", clientFinalMessage)
            
            message = clientFinalMessage
        }
        
    }
    
    /// Default client nonce length, if it needs to be automatically generated.
    public static let nonceLength: Int              = 24
    public static let initialMessageHeader: String  = "n,"
    public static let finalMessageHeader: String    = "c=biws"
    public static var debug: Bool                   = false
    
    public var initialMessage: InitialClientMessage
    public var finalClientMessage: FinalClientMessage?
    
    /// Initialize a SCRAM session
    /// - Parameters:
    ///   - username: Username
    ///   - password: Password
    ///   - nonce: Client nonce
    ///   - algorithm: Hash algorithm to use, see `HashAlgorithm`.
    public init(username: String, password: String,
                nonce: String = Random.string(of: SCRAM.nonceLength), algorithm: HashAlgorithm) {
        initialMessage = InitialClientMessage(username: username, password: password, nonce: nonce, algorithm: algorithm)
        trace("initial client message", initialMessage.base64EncodedMessage)
        trace("initial client message decoded", initialMessage.message)
    }
    
    /// Parse initial server message and produce the final client message.
    /// - Parameter base64Message: Server challenge, encoded in Base64
    /// - Throws: SCRAMError
    /// - Returns: Final client message.
    public func handleInitialServerMessage(_ base64Message: String) throws -> FinalClientMessage {
        guard let data = Data(base64Encoded: base64Message) else {
            throw SCRAMError.invalidInput("Failed to decode base64 challenge")
        }
        
        guard let challengeString = String(data: data, encoding: .utf8) else {
            throw SCRAMError.invalidInput("Failed to convert challenge to string")
        }
        
        let challenge = try InitialServerMessage(challenge: challengeString, initialMessage: initialMessage)
        
        finalClientMessage = FinalClientMessage(serverChallenge: challenge, initialMessage: self.initialMessage)
        
        return finalClientMessage!
    }
    
    /// Parse final server message.
    /// - Parameter base64Message: Server final message, encoded in Base64.
    /// - Throws: SCRAMError
    /// - Returns: True if the server signature matches our `finalClientMessage.serverSignature`
    public func handleFinalServerMessage(_ base64Message: String) throws -> Bool {
        guard let data = Data(base64Encoded: base64Message),
            let finalMessage = String(data: data, encoding: .utf8),
            finalMessage.hasPrefix("v="),
            finalMessage.count > 2
        else {
            throw SCRAMError.invalidInput("Incorrect final message format")
        }
        
        guard let receivedServerSignature = Data(base64Encoded: finalMessage.substring(from: 2)) else {
            throw SCRAMError.invalidInput("Failed to decode base64 server signature")
        }
        
        guard let finalClientMessage = self.finalClientMessage else {
            throw SCRAMError.invalidState
        }
        trace("final server message", base64Message)
        trace("decoded final server message", finalMessage)
        if finalClientMessage.serverSignature != receivedServerSignature {
            trace("server signatures do not match", "\(finalClientMessage.serverSignature.toHex()) != \(receivedServerSignature.toHex())")
        }
        return finalClientMessage.serverSignature == receivedServerSignature
    }
}
