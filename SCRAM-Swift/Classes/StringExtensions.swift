//
//  StringExtensions.swift
//  SCRAM-Swift
//
//  Created by clw on 18/06/2020.
//

import Foundation

// Substring helpers.
extension String {
    func index(from: Int) -> Index {
        return self.index(startIndex, offsetBy: from)
    }

    func substring(from: Int) -> String {
        let fromIndex = index(from: from)
        return String(self[fromIndex...])
    }

    func substring(to: Int) -> String {
        let toIndex = index(from: to)
        return String(self[..<toIndex])
    }

    func substring(with r: Range<Int>) -> String {
        let startIndex = index(from: r.lowerBound)
        let endIndex = index(from: r.upperBound)
        return String(self[startIndex..<endIndex])
    }
}

extension String {
    
    /// Convert the current string to HEX (via a Data object)
    /// - Returns: HEX string
    func toHex() -> String {
        return self.data(using: .utf8)!.toHex()
    }
    
    public func hmac(key: Data, algorithm: HashAlgorithm) -> Data {
        self.data(using: .utf8)!.hmac(key: key, algorithm: algorithm)
    }
}
