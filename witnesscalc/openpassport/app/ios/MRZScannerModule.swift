//
//  MRZScannerModule.swift
//  ProofOfPassport
//
//  Created by Rémi Colin on 27/02/2024.
//

import Foundation
import React
import SwiftUI

@objc(MRZScannerModule)
class MRZScannerModule: NSObject, RCTBridgeModule {
  static func moduleName() -> String! {
    return "MRZScannerModule"
  }

  static func requiresMainQueueSetup() -> Bool {
    return true
  }
  
  @objc func startScanning(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
      DispatchQueue.main.async {
          guard let rootViewController = UIApplication.shared.keyWindow?.rootViewController else {
              reject("error", "Unable to find root view controller", nil)
              return
          }
          
          var hostingController: UIHostingController<ScannerWithInstructions>? = nil
          var scannerView = QKMRZScannerViewRepresentable()
          let lottieView = LottieView(animationFileName: "passport", loopMode: .loop)

          scannerView.onScanResult = { scanResult in
              let resultDict: [String: Any] = [
                  "documentNumber": scanResult.documentNumber,
                  "expiryDate": scanResult.expiryDate?.description ?? "",
                  "birthDate": scanResult.birthdate?.description ?? ""
              ]
              resolve(resultDict)
              
              // Dismiss the hosting controller after scanning
              hostingController?.dismiss(animated: true, completion: nil) 
          }
          
          // Wrap the scanner view and instruction text in a new SwiftUI view
          let scannerWithInstructions = ScannerWithInstructions(scannerView: scannerView, lottieView: lottieView)
          hostingController = UIHostingController(rootView: scannerWithInstructions)
          rootViewController.present(hostingController!, animated: true, completion: nil)
      }
  }

  @objc func stopScanning(_ resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
    // Logic to stop scanning
    resolve("Scanning stopped")
  }
}
// Define a new SwiftUI view that includes the scanner and instruction text
struct ScannerWithInstructions: View {
    var scannerView: QKMRZScannerViewRepresentable
    var lottieView: LottieView
    
    var body: some View {
        ZStack {
            Color.white.ignoresSafeArea() // This creates a white background for the entire view
            
            VStack {
                ZStack {
                    scannerView
                        .mask {
                            RoundedRectangle(cornerRadius: 15)
                                .frame(width: 370, height: 270)
                        }
                    lottieView.frame(width: 360, height: 230)
                }
                .frame(height: 320)
                Text("Hold your passport on a flat surface while scanning")
                    .font(.custom("Inter-Regular", size: 20))
                    .foregroundColor(.black)
                    .multilineTextAlignment(.center)
                    .frame(width: 300)
                    .padding()
            }
        }
    }
}