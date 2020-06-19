//
//  DataExtensions.swift
//  SCRAM-Swift
//
//  Created by Alin Radut on 18/06/2020.
//

import Foundation
import CommonCrypto

extension Data {
    
    /// XOR the current data with the given key.
    /// If the key is smaller than the current data, the key will be rolled.
    /// - Parameter key: Key
    /// - Returns: Data
    func xored(with key: Data) -> Data {
        var output = self
        for i in 0..<self.count {
            output[i] ^= key[i % key.count]
        }
        return output
    }
}

extension Data {
    
    /// Convert data to a HEX string.
    /// - Returns: HEX string
    func toHex() -> String {
        var str: String = String()
        let bytes = (self as NSData).bytes.bindMemory(to: UInt8.self, capacity: self.count)
        let len = self.count
        
        for index in 0 ..< len {
            str += String(format: "%02.2X", bytes[index])
        }
        return str
    }
}

extension Data {
    
    /// Produce a HMAC using the current data and the given key.
    /// - Parameters:
    ///   - key: Key
    ///   - algorithm: Hash algorithm
    /// - Returns: Hmac
    func hmac(key: String, algorithm: HashAlgorithm) -> Data {
        var output = Data(count: Int(algorithm.digestLength))
        output.withUnsafeMutableBytes { outputBytes in
            CCHmac(
                algorithm.hmac,
                (self as NSData).bytes,
                self.count,
                key,
                key.count,
                outputBytes)
        }
        return output
    }
    
    /// Produce a hash for the current data.
    /// - Parameter algorithm: Hash algorithm
    /// - Returns: Data
    func hash(algorithm: HashAlgorithm) -> Data {
        switch algorithm {
        case .sha1:
            return sha1()
        case .sha256:
            return sha256()
        case .sha512:
            return sha512()
        }
    }
    
    func sha1() -> Data {
        var output = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
        
        output.withUnsafeMutableBytes { (bytes) -> Void in
            CC_SHA1((self as NSData).bytes, CC_LONG(self.count), bytes)
        }
        
        return output
    }
    
    func sha256() -> Data {
        var output = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        
        output.withUnsafeMutableBytes { (bytes) -> Void in
            CC_SHA256((self as NSData).bytes, CC_LONG(self.count), bytes)
        }
        
        return output
    }
    
    func sha512() -> Data {
        var output = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
        
        output.withUnsafeMutableBytes { (bytes) -> Void in
            CC_SHA512((self as NSData).bytes, CC_LONG(self.count), bytes)
        }
        
        return output
    }
    
    /// Run a PBKDF using the given algorithm.
    /// - Parameters:
    ///   - salt: Salt
    ///   - algorithm: Algorithm
    ///   - iterations: Number of iterations
    /// - Returns: Derived key
    func derive(salt: Data, algorithm: HashAlgorithm, iterations: Int) -> Data {
        var output = Data(count: Int(algorithm.digestLength))
        
        output.withUnsafeMutableBytes { (outputBytes) -> Void in
            self.withUnsafeBytes { (selfBytes) -> Void in
                salt.withUnsafeBytes { (saltBytes) -> Void in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        selfBytes,
                        self.count,
                        saltBytes,
                        salt.count,
                        algorithm.prf,
                        UInt32(iterations),
                        outputBytes,
                        Int(algorithm.digestLength))

                }
            }
        }
        
        return output
    }
}
