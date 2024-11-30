requires 0 "67 66 43 53"
little_endian

proc formatType {type} {
	switch -- $type {
		"AICl" {return "Accelerator Interrupt Calibration"}
		"ARot" {return "Accelerator Orientation Calibration"}
		"ARNC" {return "Accelerator Range Interior Calibration"}
		"AROC" {return "Accelerator Offset Calibration"}
		"ARSC" {return "Accelerator Range Sensitivity Calibration"}
		"ARXC" {return "Accelerator Range Exterior Calibration"}
		"ARXN" {return "Accelerator Nominal Exterior Calibration"}
		"ASCi" {return "? Calibration Data"}
		"ASCl" {return "Accelerator Sensitivity Calibration"}
		"BCAL" {return "Bluetooth Taurus Calibration"}
		"BCAR" {return "Back Camera Autofocus Recalibration"}
		"BCMB" {return "Back Camera Module Board"}
		"BCMS" {return "Back Camera Module Serial Number"}
		"BGMt" {return "Backing Glass Material"}
		"BLCl" {return "Backlight Calibration"}
		"BMac" {return "Bluetooth Mac Address"}
		"BTBF" {return "Bluetooth Taurus Calibration BF"}
		"BTRx" {return "Bluetooth Reception Calibration"}
		"BTTx" {return "Bluetooth Transmission Calibration"}
		"Batt" {return "Battery Serial Number"}
		"CBAT" {return "Charger Input Limit Calibration"}
		"CBCC" {return "Compass Battery Compensation"}
		"CDCC" {return "Compass Hilo Compensation"}
		"CFG#" {return "Configuration Number"}
		"CGMt" {return "Coverglass Material"}
		"CGSp" {return "Coverglass Type"}
		"CLHS" {return "Housing Color"}
		"CLCG" {return "Coverglass Color"}
		"CLCL" {return "Controller Coefficient Calibration"}
		"CMOC" {return "Compass Mode Offset Compensation"}
		"CNTB" {return "CNTB Block"}
		"CPAS" {return "Compass Calibration"}
		"CRot" {return "Compass Orientation"}
		"CSCM" {return "Compass Sensor Calibration"}
		"CVCC" {return "Compass VBUS Compensation"}
		"DBCl" {return "Display Backlight Compensation"}
		"DClr" {return "Device Color"}
		"DPCl" {return "Primary Calibration Matrix"}
		"DTCl" {return "Display Temperature Calibration"}
		"EMac" {return "Ethernet 0 Mac Address"}
		"EMc2" {return "Ethernet 1 Mac Address"}
		"EnMt" {return "Enclosure Material"}
		"FCMB" {return "Front Camera Module Board"}
		"FCMS" {return "Front Camera Module Serial Number"}
		"FDAC" {return "Orb Dynamic Accelerator Calibration"}
		"FG2G" {return "WiFi Calibration Frequency Group 2G"}
		"GICl" {return "Gyro Interrupt Calibration"}
		"GLCl" {return "Gamma Tables Calibration"}
		"GRot" {return "Gyro Orientation Calibration"}
		"GRSC" {return "Gyro Range Sensitivity Calibration"}
		"GRNC" {return "Gyro Range Interior Calibration"}
		"GRXC" {return "Gyro Range Exterior Calibration"}
		"GRXN" {return "Gyro Nominal Exterior Calibration"}
		"GSCi" {return "Gyro Sensitivity Matrix Inverse"}
		"GSCl" {return "Gyro Sensitivity Calibration"}
		"GTCl" {return "Gyro Trim Calibration"}
		"GYTT" {return "Gyro Temp. Calibration"}
		"LCM#" {return "Liquid Crystal Monitor Serial Number (LCD)"}
		"LSCI" {return "Ambient Lightsensor Calibration"}
		"LTAO" {return "Low Temperature Accelerator Offset"}
		"MiGa" {return "Microphone Trim Gains"}
		"MiGH" {return "Microphone Trim Gains 0"}
		"MiGT" {return "Microphone Trim Gains 1"}
		"MLB#" {return "Main Logic Board Serial Number"}
		"MdlC" {return "Murata WiFi Configuration"}
		"MkBS" {return "Marketing Software Behavior"}
		"Mod#" {return "Model Number"}
		"MtCl" {return "Multitouch Calibration"}
		"MtSN" {return "Multitouch Serial Number"}
		"NFCl" {return "Stockholm NFC Calibration"}
		"NSrN" {return "Touch ID Serial Number"}
		"NoCl" {return "Write Cal Data Inhibit"}
		"NvSn" {return "Apple SandDollar Serial Number"}
		"OFCl" {return "Orb Force Calibration"}
		"OrbC" {return "Orb Calibration"}
		"OrbG" {return "Orb Gap Calibration"}
		"PrCL" {return "Pearl Calibration Data"}
		"PrAS" {return "Pressure Acceleration Sensitivity"}
		"PRTT" {return "Pressure Temperature Compensation Table"}
		"PRSq" {return "DUT SysCfg Key"}
		"PSCl" {return "Halle Calibration"}
		"PTPM" {return "Pearl HW Metrics"}
		"PxCl" {return "Proximity Calibration"}
		"RACa" {return "Photon Detector Calibration Data"}
		"RFEM" {return "WiFi RFEM Information"}
		"RMd#" {return "Regulatory Model Number"}
		"rpsp" {return "Repair Status"}
		"RxCL" {return "Rosaline Calibration Current"}
		"Regn" {return "Region Code"}
		"SBVr" {return "Software Bundle Version"}
		"SPPO" {return "Pressure Offset Calibration"}
		"SpCl" {return "Speaker Trim Gains 1"}
		"SpGa" {return "Speaker Trim Gains"}
		"SpGH" {return "Speaker Trim Gains 0"}
		"SpPH" {return "Speaker Thiele Small 0"}
		"SpPT" {return "Speaker Thiele Small 1"}
		"SpTS" {return "Speaker Thiele Small"}
		"SrNm" {return "Device Serial Number"}
		"STRB" {return "Camera Strobe Color Calibration"}
		"SwBh" {return "Software Behaviour Bits"}
		"TCal" {return "Audio Actuator Calibration"}
		"VBCA" {return "Speaker Configuration"}
		"VBST" {return "Speaker Configuration"}
		"VPBR" {return "Speaker Configuration"}
		"W24R" {return "WiFi Receiver 2.4Ghz Calibration"}
		"WCAL" {return "WiFi Calibration"}
		"WMac" {return "WiFi 0 MAC Address"}
		"WRxT" {return "WiFi Receiver Temp. Calibration"}
		"WSKU" {return "WiFi Antenna SKU Information"}
		default {return "Unknown"}
	}
}

section "SysCfg Header" {
	entry "Magic" [string reverse [ascii 4]] [move -4; format 4]; move 4
	uint32 -hex	"Size"
	uint32 -hex	"Max Size"
	uint32 -hex	"Version"
	uint32   	"Big Endian"
	set kc [uint32 -hex	"Key Count"]
} 

for {set i 0} {$i < $kc} {incr i} {
    section "SysCfg Entry" {
        set tag [string reverse [ascii 4]]
        entry "Tag" [format "%s (%s)" [formatType $tag] $tag] [move -4; format 4]; move 4
        if {$tag in {"SrNm" "Mod#" "Batt" "MLB#" "Regn" "PTPM" "RMd#"}} {
            ascii 16 "Data"
        } elseif {$tag == "CNTB"} {
        	section "CNTB" {
        		set cntbtag [string reverse [ascii 4]]
        		entry "Tag" [format "%s (%s)" [formatType $cntbtag] $cntbtag] [move -4; format 4]; move 4
        		set sz [uint32 -hex "Data Size"]
        		set off [uint32 -hex "Data Offset"]
        		bytes 4
        		set curpos [pos]
        		goto $off
        		bytes $sz "Data"
        		goto $curpos
        	}
        } elseif {$tag in {"WMac" "EMac" "BMac"}} {
        	entry "MAC" [format "%X:%X:%X:%X:%X:%X" [uint8] [uint8] [uint8] [uint8] [uint8] [uint8]] [move -6; format 6]; move 6
        	bytes 10
        } elseif {$tag == "DaTi"} {
            set data [ascii 14]
            set dt [clock scan $data -format %Y%m%d%H%M%S]
            entry "Time" [clock format $dt -format "%a %b %d %Y %T"] [move -14; format 16]; move 16
        } else {
            bytes 16 "Data"
        }
    }
}