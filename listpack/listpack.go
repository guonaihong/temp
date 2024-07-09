package listpack

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"unsafe"
)

const (
	LP_HDR_SIZE                      = 6 // 32位总长度 + 16位元素数量
	LP_HDR_NUMELE_UNKNOWN            = math.MaxUint16
	LP_MAX_INT_ENCODING_LEN          = 9
	LP_MAX_BACKLEN_SIZE              = 5
	LP_ENCODING_INT                  = 0
	LP_ENCODING_STRING               = 1
	LP_ENCODING_7BIT_UINT            = 0
	LP_ENCODING_7BIT_UINT_MASK       = 0x80
	LP_ENCODING_IS_7BIT_UINT         = 0x80
	LP_ENCODING_7BIT_UINT_ENTRY_SIZE = 2
	LP_ENCODING_6BIT_STR             = 0x80
	LP_ENCODING_6BIT_STR_MASK        = 0xC0
	LP_ENCODING_IS_6BIT_STR          = 0x80
	LP_ENCODING_13BIT_INT            = 0xC0
	LP_ENCODING_13BIT_INT_MASK       = 0xE0
	LP_ENCODING_IS_13BIT_INT         = 0xC0
	LP_ENCODING_13BIT_INT_ENTRY_SIZE = 3
	LP_ENCODING_12BIT_STR            = 0xE0
	LP_ENCODING_12BIT_STR_MASK       = 0xF0
	LP_ENCODING_IS_12BIT_STR         = 0xE0
	LP_ENCODING_16BIT_INT            = 0xF1
	LP_ENCODING_16BIT_INT_MASK       = 0xFF
	LP_ENCODING_IS_16BIT_INT         = 0xF1
	LP_ENCODING_16BIT_INT_ENTRY_SIZE = 4
	LP_ENCODING_24BIT_INT            = 0xF2
	LP_ENCODING_24BIT_INT_MASK       = 0xFF
	LP_ENCODING_IS_24BIT_INT         = 0xF2
	LP_ENCODING_24BIT_INT_ENTRY_SIZE = 5
	LP_ENCODING_32BIT_INT            = 0xF3
	LP_ENCODING_32BIT_INT_MASK       = 0xFF
	LP_ENCODING_IS_32BIT_INT         = 0xF3
	LP_ENCODING_32BIT_INT_ENTRY_SIZE = 6
	LP_ENCODING_64BIT_INT            = 0xF4
	LP_ENCODING_64BIT_INT_MASK       = 0xFF
	LP_ENCODING_IS_64BIT_INT         = 0xF4
	LP_ENCODING_64BIT_INT_ENTRY_SIZE = 10
	LP_ENCODING_32BIT_STR            = 0xF0
	LP_ENCODING_32BIT_STR_MASK       = 0xFF
	LP_ENCODING_IS_32BIT_STR         = 0xF0
	LP_EOF                           = 0xFF
	LP_INTBUF_SIZE                   = 21 // 20位数字 + 1位空终止符
)

// 获取总字节数
func lpGetTotalBytes(lp []byte) uint32 {
	return uint32(lp[0]) | uint32(lp[1])<<8 | uint32(lp[2])<<16 | uint32(lp[3])<<24
}

// 设置总字节数
func lpSetTotalBytes(lp []byte, v uint32) {
	lp[0] = byte(v)
	lp[1] = byte(v >> 8)
	lp[2] = byte(v >> 16)
	lp[3] = byte(v >> 24)
}

// 获取元素数量
func lpGetNumElements(lp []byte) uint16 {
	return uint16(lp[4]) | uint16(lp[5])<<8
}

// 设置元素数量
func lpSetNumElements(lp []byte, v uint16) {
	lp[4] = byte(v)
	lp[5] = byte(v >> 8)
}

// 创建一个新的listpack
func lpNew(capacity int) []byte {
	if capacity < LP_HDR_SIZE+1 {
		capacity = LP_HDR_SIZE + 1
	}
	lp := make([]byte, capacity)
	lpSetTotalBytes(lp, uint32(LP_HDR_SIZE+1))
	lpSetNumElements(lp, 0)
	lp[LP_HDR_SIZE] = LP_EOF
	return lp
}

// 释放listpack
func lpFree(lp []byte) {
	// Go语言中不需要手动释放内存
}

// 缩小listpack以适应实际大小
func lpShrinkToFit(lp []byte) []byte {
	size := lpGetTotalBytes(lp)
	if size < uint32(cap(lp)) {
		newLp := make([]byte, size)
		copy(newLp, lp)
		return newLp
	}
	return lp
}

// 插入字符串元素
func lpInsertString(lp []byte, s []byte, p []byte, where int, newp *[]byte) ([]byte, error) {
	return lpInsert(lp, s, nil, len(s), p, where, newp)
}

// 插入整数元素
func lpInsertInteger(lp []byte, lval int64, p []byte, where int, newp *[]byte) ([]byte, error) {
	intenc := make([]byte, LP_MAX_INT_ENCODING_LEN)
	enclen := lpEncodeIntegerGetType(lval, intenc)
	return lpInsert(lp, nil, intenc, enclen, p, where, newp)
}

// 在头部插入字符串元素
func lpPrepend(lp []byte, s []byte) ([]byte, error) {
	p := lpFirst(lp)
	if p == nil {
		return lpAppend(lp, s)
	}
	return lpInsertString(lp, s, p, LP_BEFORE, nil)
}

// 在头部插入整数元素
func lpPrependInteger(lp []byte, lval int64) ([]byte, error) {
	p := lpFirst(lp)
	if p == nil {
		return lpAppendInteger(lp, lval)
	}
	return lpInsertInteger(lp, lval, p, LP_BEFORE, nil)
}

// 在尾部插入字符串元素
func lpAppend(lp []byte, s []byte) ([]byte, error) {
	listpackBytes := lpGetTotalBytes(lp)
	eofptr := lp[listpackBytes-1:]
	return lpInsertString(lp, s, eofptr, LP_BEFORE, nil)
}

// 在尾部插入整数元素
func lpAppendInteger(lp []byte, lval int64) ([]byte, error) {
	listpackBytes := lpGetTotalBytes(lp)
	eofptr := lp[listpackBytes-1:]
	return lpInsertInteger(lp, lval, eofptr, LP_BEFORE, nil)
}

// 替换当前元素
func lpReplace(lp []byte, p *[]byte, s []byte) ([]byte, error) {
	return lpInsertString(lp, s, *p, LP_REPLACE, p)
}

// 替换当前整数元素
func lpReplaceInteger(lp []byte, p *[]byte, lval int64) ([]byte, error) {
	return lpInsertInteger(lp, lval, *p, LP_REPLACE, p)
}

// 删除当前元素
func lpDelete(lp []byte, p []byte, newp *[]byte) ([]byte, error) {
	return lpInsert(lp, nil, nil, 0, p, LP_REPLACE, newp)
}

// 删除范围内的元素
func lpDeleteRangeWithEntry(lp []byte, p *[]byte, num uint) ([]byte, error) {
	bytes := lpBytes(lp)
	deleted := 0
	first := *p
	tail := first

	if num == 0 {
		return lp, nil
	}

	for num > 0 {
		deleted++
		tail = lpSkip(tail)
		if tail[0] == LP_EOF {
			break
		}
		num--
	}

	poff := first - lp
	memmove(first, tail, lp[bytes-1:]-tail+1)
	lpSetTotalBytes(lp, bytes-(tail-first))
	numele := lpGetNumElements(lp)
	if numele != LP_HDR_NUMELE_UNKNOWN {
		lpSetNumElements(lp, numele-uint16(deleted))
	}
	lp = lpShrinkToFit(lp)

	*p = lp[poff:]
	if (*p)[0] == LP_EOF {
		*p = nil
	}

	return lp, nil
}

// 删除范围内的元素
func lpDeleteRange(lp []byte, index int, num uint) ([]byte, error) {
	p, err := lpSeek(lp, index)
	if err != nil {
		return lp, err
	}

	numele := lpGetNumElements(lp)
	if numele != LP_HDR_NUMELE_UNKNOWN && index < 0 {
		index = int(numele) + index
	}
	if numele != LP_HDR_NUMELE_UNKNOWN && uint(numele)-uint(index) <= num {
		p[0] = LP_EOF
		lpSetTotalBytes(lp, p-lp+1)
		lpSetNumElements(lp, uint16(index))
		lp = lpShrinkToFit(lp)
	} else {
		lp, err = lpDeleteRangeWithEntry(lp, &p, num)
	}

	return lp, err
}

// 批量删除元素
func lpBatchDelete(lp []byte, ps [][]byte, count uint) ([]byte, error) {
	if count == 0 {
		return lp, nil
	}

	dst := ps[0]
	totalBytes := lpGetTotalBytes(lp)
	lpEnd := lp[totalBytes-1:]

	for i := 0; i < int(count); i++ {
		skip := ps[i]
		keepStart := lpSkip(skip)
		var keepEnd []byte
		if i+1 < int(count) {
			keepEnd = ps[i+1]
			if keepStart == keepEnd {
				continue
			}
		} else {
			keepEnd = lpEnd
		}
		bytesToKeep := keepEnd - keepStart
		memmove(dst, keepStart, bytesToKeep)
		dst += bytesToKeep
	}

	deletedBytes := lpEnd - dst
	totalBytes -= deletedBytes
	lpSetTotalBytes(lp, totalBytes)
	numele := lpGetNumElements(lp)
	if numele != LP_HDR_NUMELE_UNKNOWN {
		lpSetNumElements(lp, numele-uint16(count))
	}

	return lpShrinkToFit(lp), nil
}

// 合并两个listpack
func lpMerge(first *[]byte, second *[]byte) ([]byte, error) {
	if first == nil || *first == nil || second == nil || *second == nil {
		return nil, errors.New("invalid listpack pointers")
	}

	if *first == *second {
		return nil, errors.New("cannot merge same listpack into itself")
	}

	firstBytes := lpBytes(*first)
	secondBytes := lpBytes(*second)
	firstLen := lpLength(*first)
	secondLen := lpLength(*second)

	var target []byte
	var targetBytes uint32
	var source []byte
	var sourceBytes uint32
	var append bool

	if firstBytes >= secondBytes {
		target = *first
		targetBytes = firstBytes
		source = *second
		sourceBytes = secondBytes
		append = true
	} else {
		target = *second
		targetBytes = secondBytes
		source = *first
		sourceBytes = firstBytes
		append = false
	}

	lpbytes := uint64(firstBytes) + uint64(secondBytes) - uint64(LP_HDR_SIZE) - 1
	if lpbytes > math.MaxUint32 {
		return nil, errors.New("listpack size overflow")
	}
	lplength := firstLen + secondLen
	if lplength > math.MaxUint16 {
		lplength = math.MaxUint16
	}

	target = lpRealloc(target, uint32(lpbytes))
	if append {
		memcpy(target[targetBytes-1:], source[LP_HDR_SIZE:], sourceBytes-LP_HDR_SIZE)
	} else {
		memmove(target[sourceBytes-1:], target[LP_HDR_SIZE:], targetBytes-LP_HDR_SIZE)
		memcpy(target, source, sourceBytes-1)
	}

	lpSetNumElements(target, uint16(lplength))
	lpSetTotalBytes(target, uint32(lpbytes))

	if append {
		lpFree(*second)
		*second = nil
		*first = target
	} else {
		lpFree(*first)
		*first = nil
		*second = target
	}

	return target, nil
}

// 复制listpack
func lpDup(lp []byte) []byte {
	size := lpBytes(lp)
	newLp := make([]byte, size)
	copy(newLp, lp)
	return newLp
}

// 获取listpack的字节数
func lpBytes(lp []byte) uint32 {
	return lpGetTotalBytes(lp)
}

// 估计重复整数的字节数
func lpEstimateBytesRepeatedInteger(lval int64, rep uint) uint32 {
	intenc := make([]byte, LP_MAX_INT_ENCODING_LEN)
	enclen := lpEncodeIntegerGetType(lval, intenc)
	backlen := lpEncodeBacklen(nil, enclen)
	return uint32(LP_HDR_SIZE + (enclen+backlen)*rep + 1)
}

// 查找指定索引的元素
func lpSeek(lp []byte, index int) ([]byte, error) {
	forward := true

	numele := lpGetNumElements(lp)
	if numele != LP_HDR_NUMELE_UNKNOWN {
		if index < 0 {
			index = int(numele) + index
		}
		if index < 0 {
			return nil, errors.New("index out of range")
		}
		if index >= int(numele) {
			return nil, errors.New("index out of range")
		}
		if index > int(numele)/2 {
			forward = false
			index -= int(numele)
		}
	} else {
		if index < 0 {
			forward = false
		}
	}

	if forward {
		p := lpFirst(lp)
		for index > 0 && p != nil {
			p = lpNext(lp, p)
			index--
		}
		return p, nil
	} else {
		p := lpLast(lp)
		for index < -1 && p != nil {
			p = lpPrev(lp, p)
			index++
		}
		return p, nil
	}
}

// 验证listpack的完整性
func lpValidateIntegrity(lp []byte, size uint32, deep bool, entryCb func([]byte, uint, interface{}) bool, userdata interface{}) bool {
	if size < LP_HDR_SIZE+1 {
		return false
	}

	bytes := lpGetTotalBytes(lp)
	if bytes != size {
		return false
	}

	if lp[size-1] != LP_EOF {
		return false
	}

	if !deep {
		return true
	}

	count := uint(0)
	numele := lpGetNumElements(lp)
	p := lp + LP_HDR_SIZE
	for p != nil && p[0] != LP_EOF {
		prev := p
		if !lpValidateNext(lp, &p, size) {
			return false
		}
		if entryCb != nil && !entryCb(prev, numele, userdata) {
			return false
		}
		count++
	}

	if p != lp+size-1 {
		return false
	}

	if numele != LP_HDR_NUMELE_UNKNOWN && numele != count {
		return false
	}

	return true
}

// 比较元素
func lpCompare(p []byte, s []byte, slen uint32) bool {
	vstr, vlen := lpGet(p)
	if vstr != nil {
		return slen == vlen && bytes.Equal(vstr, s)
	} else {
		sval, err := strconv.ParseInt(string(s), 10, 64)
		if err != nil {
			return false
		}
		return vlen == sval
	}
}

// 随机选择一对键值
func lpRandomPair(lp []byte, totalCount uint, key *listpackEntry, val *listpackEntry) {
	r := rand.Intn(int(totalCount)) * 2
	p, _ := lpSeek(lp, r)
	key.sval, key.slen = lpGetValue(p)
	p, _ = lpNext(lp, p)
	val.sval, val.slen = lpGetValue(p)
}

// 随机选择多个元素
func lpRandomEntries(lp []byte, count uint, entries []listpackEntry) {
	picks := make([]struct {
		index uint
		order uint
	}, count)
	totalSize := lpLength(lp)
	for i := uint(0); i < count; i++ {
		picks[i].index = uint(rand.Intn(int(totalSize)))
		picks[i].order = i
	}

	// 按索引排序
	sort.Slice(picks, func(i, j int) bool {
		return picks[i].index < picks[j].index
	})

	// 按原始顺序存储值
	p := lpFirst(lp)
	j := 0
	for i := uint(0); i < count; i++ {
		for j < int(picks[i].index) {
			p, _ = lpNext(lp, p)
			j++
		}
		storeOrder := picks[i].order
		entries[storeOrder].sval, entries[storeOrder].slen = lpGetValue(p)
	}
}

// 随机选择多个键值对
func lpRandomPairs(lp []byte, count uint, keys []listpackEntry, vals []listpackEntry) {
	p := lpFirst(lp)
	for i := uint(0); i < count; i++ {
		p, _ = lpNextRandom(lp, p, nil, 1, 0)
		keys[i].sval, keys[i].slen = lpGetValue(p)
		p, _ = lpNext(lp, p)
		vals[i].sval, vals[i].slen = lpGetValue(p)
	}
}

// 随机选择多个唯一的键值对
func lpRandomPairsUnique(lp []byte, count uint, keys []listpackEntry, vals []listpackEntry) uint {
	p := lpFirst(lp)
	picked := uint(0)
	remaining := count
	for picked < count && p != nil {
		p, _ = lpNextRandom(lp, p, nil, remaining, 1)
		keys[picked].sval, keys[picked].slen = lpGetValue(p)
		p, _ = lpNext(lp, p)
		vals[picked].sval, vals[picked].slen = lpGetValue(p)
		p, _ = lpNext(lp, p)
		remaining--
		picked++
	}
	return picked
}

// 随机选择下一个元素
func lpNextRandom(lp []byte, p []byte, index *uint, remaining uint, evenOnly int) ([]byte, error) {
	if p == nil {
		return nil, errors.New("invalid pointer")
	}

	if remaining == 0 {
		return nil, nil
	}

	if evenOnly != 0 && *index%2 != 0 {
		p, _ = lpNext(lp, p)
		*index++
		return p, nil
	}

	available := remaining
	if evenOnly != 0 {
		available /= 2
	}
	randomDouble := rand.Float64()
	threshold := float64(remaining) / float64(available)
	if randomDouble <= threshold {
		return p, nil
	}

	p, _ = lpNext(lp, p)
	*index++
	return p, nil
}

// 安全检查是否可以添加元素
func lpSafeToAdd(lp []byte, add uint) bool {
	len := lpGetTotalBytes(lp)
	if len+uint32(add) > math.MaxUint32 {
		return false
	}
	return true
}

// 打印listpack信息
func lpRepr(lp []byte) {
	p, _ := lpFirst(lp)
	index := 0
	for p != nil {
		encodedSizeBytes := lpCurrentEncodedSizeBytes(p)
		encodedSize := lpCurrentEncodedSizeUnsafe(p)
		backLen := lpEncodeBacklen(nil, encodedSize)
		payloadSize := encodedSize - encodedSizeBytes

		vstr, vlen := lpGet(p)
		if vlen > 40 {
			vstr = vstr[:40]
		}

		fmt.Printf(
			"{\n"+
				"\taddr: 0x%08x,\n"+
				"\tindex: %2d,\n"+
				"\toffset: %1d,\n"+
				"\thdr+entrylen+backlen: %2d,\n"+
				"\thdrlen: %3d,\n"+
				"\tbacklen: %2d,\n"+
				"\tpayload: %1d\n"+
				"\tbytes: %v\n"+
				"\t[str]%s\n"+
				"}\n",
			uintptr(unsafe.Pointer(&p[0])),
			index,
			p-lp,
			encodedSize+backLen,
			encodedSizeBytes,
			backLen,
			payloadSize,
			p[:encodedSize+backLen],
			string(vstr),
		)

		index++
		p, _ = lpNext(lp, p)
	}
	fmt.Printf("{end}\n\n")
}

// 辅助函数：内存移动
func memmove(dst []byte, src []byte, len int) {
	copy(dst, src[:len])
}

// 辅助函数：内存复制
func memcpy(dst []byte, src []byte, len int) {
	copy(dst, src[:len])
}

// 辅助函数：重新分配内存
func lpRealloc(lp []byte, size uint32) []byte {
	newLp := make([]byte, size)
	copy(newLp, lp)
	return newLp
}

// 辅助函数：获取元素值
func lpGet(p []byte) ([]byte, int64) {
	if LP_ENCODING_IS_7BIT_UINT(p[0]) {
		return nil, int64(p[0] & 0x7F)
	}
	if LP_ENCODING_IS_6BIT_STR(p[0]) {
		return p[1 : 1+LP_ENCODING_6BIT_STR_LEN(p)], 0
	}
	if LP_ENCODING_IS_13BIT_INT(p[0]) {
		return nil, int64((p[0]&0x1F)<<8 | p[1])
	}
	if LP_ENCODING_IS_16BIT_INT(p[0]) {
		return nil, int64(p[1] | p[2]<<8)
	}
	if LP_ENCODING_IS_24BIT_INT(p[0]) {
		return nil, int64(p[1] | p[2]<<8 | p[3]<<16)
	}
	if LP_ENCODING_IS_32BIT_INT(p[0]) {
		return nil, int64(p[1] | p[2]<<8 | p[3]<<16 | p[4]<<24)
	}
	if LP_ENCODING_IS_64BIT_INT(p[0]) {
		return nil, int64(p[1] | p[2]<<8 | p[3]<<16 | p[4]<<24 | p[5]<<32 | p[6]<<40 | p[7]<<48 | p[8]<<56)
	}
	if LP_ENCODING_IS_12BIT_STR(p[0]) {
		return p[2 : 2+LP_ENCODING_12BIT_STR_LEN(p)], 0
	}
	if LP_ENCODING_IS_32BIT_STR(p[0]) {
		return p[5 : 5+LP_ENCODING_32BIT_STR_LEN(p)], 0
	}
	return nil, 0
}

// 辅助函数：获取元素值
func lpGetValue(p []byte) ([]byte, uint32) {
	vstr, vlen := lpGet(p)
	if vstr != nil {
		return vstr, uint32(vlen)
	}
	return nil, uint32(vlen)
}

// 辅助函数：获取当前编码大小
func lpCurrentEncodedSizeBytes(p []byte) uint32 {
	if LP_ENCODING_IS_7BIT_UINT(p[0]) {
		return 1
	}
	if LP_ENCODING_IS_6BIT_STR(p[0]) {
		return 1
	}
	if LP_ENCODING_IS_13BIT_INT(p[0]) {
		return 1
	}
	if LP_ENCODING_IS_16BIT_INT(p[0]) {
		return 1
	}
	if LP_ENCODING_IS_24BIT_INT(p[0]) {
		return 1
	}
	if LP_ENCODING_IS_32BIT_INT(p[0]) {
		return 1
	}
	if LP_ENCODING_IS_64BIT_INT(p[0]) {
		return 1
	}
	if LP_ENCODING_IS_12BIT_STR(p[0]) {
		return 2
	}
	if LP_ENCODING_IS_32BIT_STR(p[0]) {
		return 5
	}
	return 0
}

// 辅助函数：获取当前编码大小
func lpCurrentEncodedSizeUnsafe(p []byte) uint32 {
	if LP_ENCODING_IS_7BIT_UINT(p[0]) {
		return 1
	}
	if LP_ENCODING_IS_6BIT_STR(p[0]) {
		return 1 + LP_ENCODING_6BIT_STR_LEN(p)
	}
	if LP_ENCODING_IS_13BIT_INT(p[0]) {
		return 2
	}
	if LP_ENCODING_IS_16BIT_INT(p[0]) {
		return 3
	}
	if LP_ENCODING_IS_24BIT_INT(p[0]) {
		return 4
	}
	if LP_ENCODING_IS_32BIT_INT(p[0]) {
		return 5
	}
	if LP_ENCODING_IS_64BIT_INT(p[0]) {
		return 9
	}
	if LP_ENCODING_IS_12BIT_STR(p[0]) {
		return 2 + LP_ENCODING_12BIT_STR_LEN(p)
	}
	if LP_ENCODING_IS_32BIT_STR(p[0]) {
		return 5 + LP_ENCODING_32BIT_STR_LEN(p)
	}
	return 0
}

// 辅助函数：跳过当前元素
func lpSkip(p []byte) []byte {
	entrylen := lpCurrentEncodedSizeUnsafe(p)
	entrylen += lpEncodeBacklen(nil, entrylen)
	return p[entrylen:]
}

// 辅助函数：获取下一个元素
func lpNext(lp []byte, p []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("invalid pointer")
	}
	p = lpSkip(p)
	if p[0] == LP_EOF {
		return nil, nil
	}
	return p, nil
}

// 辅助函数：获取前一个元素
func lpPrev(lp []byte, p []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("invalid pointer")
	}
	if p-lp == LP_HDR_SIZE {
		return nil, nil
	}
	p--
	prevlen := lpDecodeBacklen(p)
	prevlen += lpEncodeBacklen(nil, prevlen)
	return p - prevlen + 1, nil
}

// 辅助函数：获取第一个元素
func lpFirst(lp []byte) []byte {
	p := lp[LP_HDR_SIZE:]
	if p[0] == LP_EOF {
		return nil
	}
	return p
}

// 辅助函数：获取最后一个元素
func lpLast(lp []byte) []byte {
	p := lp + lpGetTotalBytes(lp) - 1
	return lpPrev(lp, p)
}

// 辅助函数：获取元素数量
func lpLength(lp []byte) uint {
	numele := lpGetNumElements(lp)
	if numele != LP_HDR_NUMELE_UNKNOWN {
		return uint(numele)
	}

	count := uint(0)
	p := lpFirst(lp)
	for p != nil {
		count++
		p, _ = lpNext(lp, p)
	}

	if count < LP_HDR_NUMELE_UNKNOWN {
		lpSetNumElements(lp, uint16(count))
	}
	return count
}

// 辅助函数：编码整数类型
func lpEncodeIntegerGetType(v int64, intenc []byte) uint {
	if v >= 0 && v <= 127 {
		intenc[0] = byte(v)
		return 1
	}
	if v >= -4096 && v <= 4095 {
		if v < 0 {
			v = (1 << 13) + v
		}
		intenc[0] = byte(v>>8) | LP_ENCODING_13BIT_INT
		intenc[1] = byte(v)
		return 2
	}
	if v >= -32768 && v <= 32767 {
		if v < 0 {
			v = (1 << 16) + v
		}
		intenc[0] = LP_ENCODING_16BIT_INT
		intenc[1] = byte(v)
		intenc[2] = byte(v >> 8)
		return 3
	}
	if v >= -8388608 && v <= 8388607 {
		if v < 0 {
			v = (1 << 24) + v
		}
		intenc[0] = LP_ENCODING_24BIT_INT
		intenc[1] = byte(v)
		intenc[2] = byte(v >> 8)
		intenc[3] = byte(v >> 16)
		return 4
	}
	if v >= -2147483648 && v <= 2147483647 {
		if v < 0 {
			v = (1 << 32) + v
		}
		intenc[0] = LP_ENCODING_32BIT_INT
		intenc[1] = byte(v)
		intenc[2] = byte(v >> 8)
		intenc[3] = byte(v >> 16)
		intenc[4] = byte(v >> 24)
		return 5
	}
	uv := uint64(v)
	intenc[0] = LP_ENCODING_64BIT_INT
	intenc[1] = byte(uv)
	intenc[2] = byte(uv >> 8)
	intenc[3] = byte(uv >> 16)
	intenc[4] = byte(uv >> 24)
	intenc[5] = byte(uv >> 32)
	intenc[6] = byte(uv >> 40)
	intenc[7] = byte(uv >> 48)
	intenc[8] = byte(uv >> 56)
	return 9
}

// 辅助函数：编码反向长度
func lpEncodeBacklen(buf []byte, l uint) uint {
	if l <= 127 {
		if buf != nil {
			buf[0] = byte(l)
		}
		return 1
	}
	if l < 16383 {
		if buf != nil {
			buf[0] = byte(l >> 7)
			buf[1] = byte(l&127) | 128
		}

		return 2
	}
	if l < 2097151 {
		if buf != nil {
			buf[0] = byte(l >> 14)
			buf[1] = byte((l>>7)&127) | 128
			buf[2] = byte(l&127) | 128
		}
		return 3
	}
	if l < 268435455 {
		if buf != nil {
			buf[0] = byte(l >> 21)
			buf[1] = byte((l>>14)&127) | 128
			buf[2] = byte((l>>7)&127) | 128
			buf[3] = byte(l&127) | 128
		}
		return 4
	}
	if buf != nil {
		buf[0] = byte(l >> 28)
		buf[1] = byte((l>>21)&127) | 128
		buf[2] = byte((l>>14)&127) | 128
		buf[3] = byte((l>>7)&127) | 128
		buf[4] = byte(l&127) | 128
	}
	return 5
}

// 辅助函数：解码反向长度
func lpDecodeBacklen(p []byte) uint {
	val := uint(0)
	shift := uint(0)
	for {
		val |= uint(p[0]&127) << shift
		if p[0]&128 == 0 {
			break
		}
		shift += 7
		p--
		if shift > 28 {
			return math.MaxUint64
		}
	}
	return val
}

// 辅助函数：编码字符串
func lpEncodeString(buf []byte, s []byte, len uint) {
	if len < 64 {
		buf[0] = byte(len) | LP_ENCODING_6BIT_STR
		copy(buf[1:], s)
	} else if len < 4096 {
		buf[0] = byte(len>>8) | LP_ENCODING_12BIT_STR
		buf[1] = byte(len)
		copy(buf[2:], s)
	} else {
		buf[0] = LP_ENCODING_32BIT_STR
		buf[1] = byte(len)
		buf[2] = byte(len >> 8)
		buf[3] = byte(len >> 16)
		buf[4] = byte(len >> 24)
		copy(buf[5:], s)
	}
}

// 辅助函数：插入元素
func lpInsert(lp []byte, elestr []byte, eleint []byte, size uint, p []byte, where int, newp *[]byte) ([]byte, error) {
	intenc := make([]byte, LP_MAX_INT_ENCODING_LEN)
	backlen := make([]byte, LP_MAX_BACKLEN_SIZE)

	enclen := uint(0)
	delete := elestr == nil && eleint == nil
	if delete {
		where = LP_REPLACE
	}

	if where == LP_AFTER {
		p = lpSkip(p)
		where = LP_BEFORE
	}

	poff := p - lp

	enctype := -1
	if elestr != nil {
		enctype = lpEncodeGetType(elestr, size, intenc, &enclen)
		if enctype == LP_ENCODING_INT {
			eleint = intenc
		}
	} else if eleint != nil {
		enctype = LP_ENCODING_INT
		enclen = size
	}

	backlenSize := uint(0)
	if !delete {
		backlenSize = lpEncodeBacklen(backlen, enclen)
	}

	oldListpackBytes := lpGetTotalBytes(lp)
	var replacedLen uint
	if where == LP_REPLACE {
		replacedLen = lpCurrentEncodedSizeUnsafe(p)
		replacedLen += lpEncodeBacklen(nil, replacedLen)
	}

	newListpackBytes := oldListpackBytes + enclen + backlenSize - replacedLen
	if newListpackBytes > math.MaxUint32 {
		return nil, errors.New("listpack size overflow")
	}

	dst := lp[poff:]
	if newListpackBytes > oldListpackBytes && newListpackBytes > uint32(cap(lp)) {
		lp = lpRealloc(lp, newListpackBytes)
		dst = lp[poff:]
	}

	if where == LP_BEFORE {
		memmove(dst[enclen+backlenSize:], dst, oldListpackBytes-uint32(poff))
	} else {
		memmove(dst[enclen+backlenSize:], dst[replacedLen:], oldListpackBytes-uint32(poff)-replacedLen)
	}

	if newp != nil {
		*newp = dst
		if delete && dst[0] == LP_EOF {
			*newp = nil
		}
	}

	if !delete {
		if enctype == LP_ENCODING_INT {
			copy(dst, eleint)
		} else if elestr != nil {
			lpEncodeString(dst, elestr, size)
		}
		dst += enclen
		copy(dst, backlen)
		dst += backlenSize
	}

	if where != LP_REPLACE || delete {
		numElements := lpGetNumElements(lp)
		if numElements != LP_HDR_NUMELE_UNKNOWN {
			if !delete {
				lpSetNumElements(lp, numElements+1)
			} else {
				lpSetNumElements(lp, numElements-1)
			}
		}
	}
	lpSetTotalBytes(lp, newListpackBytes)

	return lp, nil
}

// 辅助函数：获取类型和编码长度
func lpEncodeGetType(ele []byte, size uint, intenc []byte, enclen *uint) int {
	v := int64(0)
	if lpStringToInt64(string(ele), size, &v) {
		*enclen = lpEncodeIntegerGetType(v, intenc)
		return LP_ENCODING_INT
	} else {
		if size < 64 {
			*enclen = 1 + size
		} else if size < 4096 {
			*enclen = 2 + size
		} else {
			*enclen = 5 + size
		}
		return LP_ENCODING_STRING
	}
}

// 辅助函数：字符串转整数
func lpStringToInt64(s string, slen uint, value *int64) bool {
	if slen == 0 || slen >= uint(len(s)) {
		return false
	}

	negative := false
	i := 0
	v := uint64(0)

	if s[0] == '-' {
		negative = true
		i++
		if slen == 1 {
			return false
		}
	}

	if s[i] == '0' {
		if slen == 1 {
			*value = 0
			return true
		}
		return false
	}

	if s[i] >= '1' && s[i] <= '9' {
		v = uint64(s[i] - '0')
		i++
	} else {
		return false
	}

	for i < int(slen) && s[i] >= '0' && s[i] <= '9' {
		if v > (math.MaxUint64 / 10) {
			return false
		}
		v *= 10

		if v > (math.MaxUint64 - uint64(s[i]-'0')) {
			return false
		}
		v += uint64(s[i] - '0')

		i++
	}

	if i < int(slen) {
		return false
	}

	if negative {
		if v > (uint64(-math.MinInt64+1) + 1) {
			return false
		}
		*value = -int64(v)
	} else {
		if v > math.MaxInt64 {
			return false
		}
		*value = int64(v)
	}
	return true
}
