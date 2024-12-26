package linego

// import (
// 	"utils"
// )


import (
    "fmt"
)

// 自定义错误类型
type CustomError struct {
    ErrorCode int
    Message   string
}

// 实现error接口的Error方法
func (e *CustomError) Error() string {
    return fmt.Sprintf("Error Code: %d, Message: %s", e.ErrorCode, e.Message)
}

type DummyProtocolData struct{
	id int
	dtype string
	ddata string
	subType []int
}

type DummyProtocol struct{
	protocol int
	ddata DummyProtocolData
}

type DummyThrift struct{
	name string
}


type Any interface {
}

type DummyProtocolSerializer struct {
	name string
	data Any
	protocol int
}



func (dps DummyProtocolSerializer) tobytes() ([]byte,error) {

	var data []byte
	protocolslice := []int{4, 5}
	if dps.protocol == 3 {
		data = BytesCombine([]byte{128, 1, 0, 1} ,[]byte(dps.name),[]byte{0, 0, 0, 0})
	} else if In(dps.protocol,protocolslice) {
		dps.protocol = 4
		// python: data = [130, 33, 0] + instance.getStringBytes(self.name, isCompact=True)
		length := len(dps.name)
		// fmt.Println(byte(length))
		data = BytesCombine([]byte{130, 33, 0},[]byte{byte(length)},[]byte(dps.name))
	} else {
		// python: raise ValueError(f"Unknower protocol: {protocol}")
		return []byte{},&CustomError{ErrorCode:1,Message:"Unknower protocol"}
	}
	if dps.data == nil {
		fmt.Println(dps.data)
		// python: data += instance.generateDummyProtocolField(self.data, protocol) + [0]
		bdata,_ := GenerateDummyProtocolField(dps.data, dps.protocol)
		data = BytesCombine(data, bdata, []byte{0})
	} else{
		fmt.Println(dps.data)
		data = BytesCombine(data, []byte{0})
	}
	
	
	return data,nil
}

func GenerateDummyProtocolField(params Any, proto int) ([]byte,error) {
	// isCompact := false
	data := []byte{}

	for param := range params {
		_type := param[0]
		// _id := param[1]
		_data := param[2]
		if _data == -1{
			continue
		}
		if _type == 13{
			if _data[2] == -1 {
				continue
			}
		} else if In(_type,[]int{14, 15}) {
			if _data[1] == -1 {
				continue
			}
		}
		if proto == 4 {
			if _type == 2{
				// data += tcp.getFieldHeader(0x01 if _data else 0x02, _id)
				// data = BytesCombine
				continue
			}else if _type == 98{
				// data += [152]
				//data += self.generateDummyProtocolData(_data, 11, isCompact)
				//
				continue
			}
			// data += tcp.getFieldHeader(tcp.CTYPES[_type], _id)
			// isCompact = True
		}
		// data += self.generateDummyProtocolData(_data, _type, isCompact)
	}
	return data,nil
}

// func GenerateDummyProtocolData(_data []int, ttype int, isCompact bool) ([]byte,error) {
// 	data := []byte{}
// 	if isCompact {
// 		proto := 4
// 	}else {
// 		proto := 3
// 	}

// 	if ttype == 2 {
// 		if isCompact {
// 			//data += tcp.writeByte(0x01 if _data else 0x02)
// 		} else {
// 			if _data {
// 				data = BytesCombine(data,[]byte{1})
// 			} else {
// 				data = BytesCombine(data,[]byte{0})
// 			}
// 		}
// 	} else if ttype == 3 {
// 		if isCompact {
// 			// data += tcp.writeByte(_data)
// 		} else {
// 			// data += tbp.writeByte(_data)
// 		}
// 	} else if ttype == 4 {
// 		// data = self.getFloatBytes(_data, isCompact=isCompact)
// 	} else if ttype == 8 {
// 		// data += self.getIntBytes(_data, isCompact=isCompact)
// 	} else if ttype == 10 {
// 		// data += self.getIntBytes(_data, 8, isCompact=isCompact)
// 	} else if ttype == 11 {
// 		// data += self.getStringBytes(_data, isCompact=isCompact)
// 	} else if ttype == 12 {
// 		// if isinstance(_data, DummyProtocolData):
// 		//_data = thrift2dummy(_data)
// 		// data += self.generateDummyProtocolField(_data, proto) + [0]

// 	} else if ttype == 13 {
// 		// _ktype = _data[0]
// 		// _vtype = _data[1]
// 		// _vdata = _data[2]
// 		// if isCompact:
// 		// 	data += tcp.writeMapBegin(_ktype, _vtype, len(_vdata))
// 		// else:
// 		// 	data += [_ktype, _vtype] + self.getIntBytes(
// 		// 		len(_vdata), isCompact=isCompact
// 		// 	)
// 		// for vd in _vdata:
// 		// 	data += self.generateDummyProtocolData(vd, _ktype, isCompact)
// 		// 	data += self.generateDummyProtocolData(_vdata[vd], _vtype, isCompact)
// 	} else if ttype in []int{14,15} {
// 		// _vtype = _data[0]
// 		// _vdata = _data[1]
// 		// if isCompact:
// 		// 	data += tcp.writeCollectionBegin(_vtype, len(_vdata))
// 		// else:
// 		// 	data += [_vtype] + self.getIntBytes(len(_vdata), isCompact=isCompact)
// 		// for vd in _vdata:
// 		// 	data += self.generateDummyProtocolData(vd, _vtype, isCompact)

// 	} else {
// 		return []byte{},&CustomError{ErrorCode:2,Message:"[generateDummyProtocolData] not support type"}
// 	}
// 	return data,nil
// }