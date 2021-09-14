#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>

#include <vector>
#include <map>
#include <functional>

typedef unsigned int jmagic;
typedef unsigned short jversion;
typedef unsigned short jtype;
typedef unsigned short jindex;
typedef unsigned short jflag;
typedef unsigned short jcount;
typedef unsigned int jlength;
typedef unsigned char jbyte;

#define debug_printf(x) printf x

enum class Code {
    nop = 0x00,
    aconst_null = 0x01,
    iconst_m1 = 0x02,
    iconst_0 = 0x03,
    iconst_1 = 0x04,
    iconst_2 = 0x05,
    iconst_3 = 0x06,
    iconst_4 = 0x07,
    iconst_5 = 0x08,
    lconst_0 = 0x09,
    lconst_1 = 0x0A,
    fconst_0 = 0x0B,
    fconst_1 = 0x0C,
    fconst_2 = 0x0D,
    dconst_0 = 0x0E,
    dconst_1 = 0x0F,
    bipush = 0x10,//[signed char]
    sipush = 0x11,//[signed short]
    ldc = 0x12,//[byte]
    ldc_w = 0x13,//[word]
    ldc2_w = 0x14,//[word]
    aload = 0x19,//[byte]
    aload_0 = 0x2A,
    aload_1 = 0x2B,
    aload_2 = 0x2C,
    aload_3 = 0x2D,
    iload = 0x15,//[byte]
    iload_0 = 0x1A,
    iload_1 = 0x1B,
    iload_2 = 0x1C,
    iload_3 = 0x1D,
    lload = 0x16,//[byte]
    lload_0 = 0x1E,
    lload_1 = 0x1F,
    lload_2 = 0x20,
    lload_3 = 0x21,
    fload = 0x17,//[byte]
    fload_0 = 0x22,
    fload_1 = 0x23,
    fload_2 = 0x24,
    fload_3 = 0x25,
    dload = 0x18,//[byte]
    dload_0 = 0x26,
    dload_1 = 0x27,
    dload_2 = 0x28,
    dload_3 = 0x29,
    aaload = 0x32,
    iaload = 0x2E,
    laload = 0x2F,
    faload = 0x30,
    daload = 0x31,
    baload = 0x33,
    caload = 0x34,
    saload = 0x35,
    astore = 0x3A,//[byte]
    astore_0 = 0x4B,
    astore_1 = 0x4C,
    astore_2 = 0x4D,
    astore_3 = 0x4E,
    istore = 0x36,//[byte]
    istore_0 = 0x3B,
    istore_1 = 0x3C,
    istore_2 = 0x3D,
    istore_3 = 0x3E,
    lstore = 0x37,//[byte]
    lstore_0 = 0x3F,
    lstore_1 = 0x40,
    lstore_2 = 0x41,
    lstore_3 = 0x42,
    fstore = 0x38,//[byte]
    fstore_0 = 0x43,
    fstore_1 = 0x44,
    fstore_2 = 0x45,
    fstore_3 = 0x46,
    dstore = 0x39,//[byte]
    dstore_0 = 0x47,
    dstore_1 = 0x48,
    dstore_2 = 0x49,
    dstore_3 = 0x4A,
    aastore = 0x53,
    iastore = 0x4F,
    lastore = 0x50,
    fastore = 0x51,
    dastore = 0x52,
    bastore = 0x54,
    castore = 0x55,
    sastore = 0x56,
    pop = 0x57,
    pop2 = 0x58,
    dup = 0x59,
    dup_x1 = 0x5A,
    dup_x2 = 0x5B,
    dup2 = 0x5C,
    dup2_x1 = 0x5D,
    dup2_x2 = 0x5E,
    swap = 0x5F,
    iadd = 0x60,
    ladd = 0x61,
    fadd = 0x62,
    dadd = 0x63,
    isub = 0x64,
    lsub = 0x65,
    fsub = 0x66,
    dsub = 0x67,
    imul = 0x68,
    lmul = 0x69,
    fmul = 0x6A,
    dmul = 0x6B,
    idiv = 0x6C,
    ldiv_ = 0x6D,
    fdiv = 0x6E,
    ddiv = 0x6F,
    irem = 0x70,
    lrem = 0x71,
    frem = 0x72,
    drem = 0x73,
    ineg = 0x74,
    lneg = 0x75,
    fneg = 0x76,
    dneg = 0x77,
    ishl = 0x78,
    lshl = 0x79,
    ishr = 0x7A,
    lshr = 0x7B,
    iushr = 0x7C,
    lushr = 0x7D,
    iand = 0x7E,
    land = 0x7F,
    ior = 0x80,
    lor = 0x81,
    ixor = 0x82,
    lxor = 0x83,
    iinc = 0x84,//[byte(index)] [signed char(value)]
    i2l = 0x85,
    i2f = 0x86,
    i2d = 0x87,
    l2i = 0x88,
    l2f = 0x89,
    l2d = 0x8A,
    f2i = 0x8B,
    f2l = 0x8C,
    f2d = 0x8D,
    d2i = 0x8E,
    d2l = 0x8F,
    d2f = 0x90,
    i2b = 0x91,
    i2c = 0x92,
    i2s = 0x93,
    lcmp = 0x94,
    fcmpl = 0x95,
    fcmpg = 0x96,
    dcmpl = 0x97,
    dcmpg = 0x98,
    ifeq = 0x99,//[signed short(position relative to the head of this instruction)]
    ifne = 0x9A,//[signed short(position relative to the head of this instruction)]
    iflt = 0x9B,//[signed short(position relative to the head of this instruction)]
    ifge = 0x9C,//[signed short(position relative to the head of this instruction)]
    ifgt = 0x9D,//[signed short(position relative to the head of this instruction)]
    ifle = 0x9E,//[signed short(position relative to the head of this instruction)]
    if_icmpeq = 0x9F,//[signed short(position relative to the head of this instruction)]
    if_icmpne = 0xA0,//[signed short(position relative to the head of this instruction)]
    if_icmplt = 0xA1,//[signed short(position relative to the head of this instruction)]
    if_icmpge = 0xA2,//[signed short(position relative to the head of this instruction)]
    if_icmpgt = 0xA3,//[signed short(position relative to the head of this instruction)]
    if_icmple = 0xA4,//[signed short(position relative to the head of this instruction)]
    if_acmpeq = 0xA5,//[signed short(position relative to the head of this instruction)]
    if_acmpne = 0xA6,//[signed short(position relative to the head of this instruction)]
    goto_ = 0xA7,//[signed short(position relative to the head of this instruction)]
    jsr = 0xA8,
    ret = 0xA9,
    tableswitch = 0xAA,
    lookupswitch = 0xAB,
    ireturn = 0xAC,
    lreturn = 0xAD,
    freturn = 0xAE,
    dreturn = 0xAF,
    areturn = 0xB0,
    return_ = 0xB1,
    getstatic = 0xB2,//[word(index to a field)]
    putstatic = 0xB3,//[word(index to a field)]
    getfield = 0xB4,//[word(index to a field)]
    putfield = 0xB5,//[word(index to a field)]
    invokevirtual = 0xB6,//invokevirtual (WORD)[method index] __thiscall调用约定 CallObjectMethod
    invokespecial = 0xB7,//invokespecial (WORD)[method index] __thiscall调用约定 <init>
    invokestatic = 0xB8,//invokestatic (WORD)[method index] __stdcall调用约定 static
    invokeinterface = 0xB9,//invokeinterface (WORD)[method index] __thiscall调用约定 CallObjectMethod
    new_ = 0xBB,//[word(index to a class)] 如果要初始化该实例，则push入引用再以返回void的方法用invokespecial调用构造器
    newarray = 0xBC,
    anewarray = 0xBD,
    arraylength = 0xBE,
    athrow = 0xBF,
    checkcast = 0xC0,
    instanceof = 0xC1,
    monitorenter = 0xC2,
    monitorexit = 0xC3,
    wide = 0xC4,
    multianewarray = 0xC5,
    ifnull = 0xC6,
    ifnonnull = 0xC7,
    goto_w = 0xC8,//[signed int(position relative to the head of this instruction)]
    jsr_w = 0xC9,
};

#pragma region defines

#define CLASS_FILE_MAGIC 0xCAFEBABE

#define CLASS_CONSTANT_UTF8 1
#define CLASS_CONSTANT_INTEGER 3
#define CLASS_CONSTANT_FLOAT 4
#define CLASS_CONSTANT_LONG 5
#define CLASS_CONSTANT_DOUBLE 6
#define CLASS_CONSTANT_CLASS_REF 7
#define CLASS_CONSTANT_STRING 8
#define CLASS_CONSTANT_FIELD_REF 9
#define CLASS_CONSTANT_METHOD_REF 10
#define CLASS_CONSTANT_INTERFACE_METHOD_REF 11
#define CLASS_CONSTANT_NAME_AND_TYPE 12
#define CLASS_CONSTANT_METHOD_HANDLE 15
#define CLASS_CONSTANT_METHOD_TYPE 16
#define CLASS_CONSTANT_INVOKE_DYNAMIC 18

#define CLASS_ACC_PUBLIC 0x0001
#define CLASS_ACC_FINAL 0x0010
#define CLASS_ACC_SUPER 0x0020
#define CLASS_ACC_INTERFACE 0x0200
#define CLASS_ACC_ABSTRACT 0x0400
#define CLASS_ACC_SYNTHETIC 0x1000
#define CLASS_ACC_ANNOTATION 0x2000
#define CLASS_ACC_ENUM 0x4000

#define FIELD_ACC_PUBLIC 0x0001
#define FIELD_ACC_PRIVATE 0x0002
#define FIELD_ACC_PROTECTED 0x0004
#define FIELD_ACC_STATIC 0x0008
#define FIELD_ACC_FINAL 0x0010
#define FIELD_ACC_VOLATILE 0x0040
#define FIELD_ACC_TRANSIENT 0x0080
#define FIELD_ACC_SYNTHETIC 0x0100
#define FIELD_ACC_ENUM 0x0400

#define METHOD_ACC_PUBLIC 0x0001
#define METHOD_ACC_PRIVATE 0x0002
#define METHOD_ACC_PROTECTED 0x0004
#define METHOD_ACC_STATIC 0x0008
#define METHOD_ACC_FINAL 0x0010
#define METHOD_ACC_SYNCHRONIZED 0x0020
#define METHOD_ACC_BRIDGE 0x0040
#define METHOD_ACC_VARARGS 0x0080
#define METHOD_ACC_NATIVE 0x0100
#define METHOD_ACC_ABSTRACT 0x0400
#define METHOD_ACC_STRICTFP 0x0800
#define METHOD_ACC_SYNTHETIC 0x1000

#pragma endregion

class FileBuffer {
private:
    char* buffer;
    int size;
    int offset;
    int roffset;
    int increment;

    void Update(int len){
        if(offset + len < size)
            return;
        while(offset + len >= size){
            size += increment;
        }
        char* New = new char[size];
        memcpy(New, buffer, offset);
        delete[] buffer;
        buffer = New;
    }

public:
    FileBuffer(){
        buffer = new char[100];
        size = 100;
        increment = 100;
        offset = 0;
        roffset = 0;
    }

    FileBuffer(int beg, int incr){
        buffer = new char[beg];
        size = beg;
        increment = incr;
        offset = 0;
        roffset = 0;
    }

    ~FileBuffer(){
        delete[] buffer;
    }

    void* GetBuffer(){ return buffer; }

    int GetLength(){ return offset; }

    void Write(const void* buf, int len){
        Update(len);
        memcpy(buffer + offset, buf, len);
        offset += len;
    }

    void Write(char c){
        Update(1);
        buffer[offset++] = (char)c;
    }

    void Write(Code c){
        Update(1);
        buffer[offset++] = (char)c;
    }

    void WriteSwap(const void* buf, int len){
        Update(len);
        for(int i = 0; i < len; i++){
            buffer[offset++] = ((const char*)buf)[len - i - 1];
        }
    }

    void WriteShortSwap(short val){
        Update(2);
        buffer[offset++] = (char)(val >> 8);
        buffer[offset++] = val;
    }

    void WriteIntSwap(int val){
        Update(4);
        buffer[offset++] = (char)(val >> 24);
        buffer[offset++] = (char)(val >> 16);
        buffer[offset++] = (char)(val >> 8);
        buffer[offset++] = val;
    }

    void WriteTo(FILE* f){
        debug_printf(("FileBuffer::WriteTo 0x%p", f));
        fwrite(buffer, offset, 1, f);
    }

    void WriteTo(const char* name){
        debug_printf(("FileBuffer::WriteTo %s", name));
        FILE* f = fopen(name, "wb");
        fwrite(buffer, offset, 1, f);
        fclose(f);
    }

    void WriteTo(std::vector<jbyte>& vec){
        size_t size = vec.size();
        vec.resize(size + offset);
        memcpy(vec.data() + size, buffer, offset);
    }

    inline int Readable(){
        return offset - roffset;
    }

    void Read(void* buf, size_t len){
        Update(roffset + len - offset);
        memcpy(buf, buffer + roffset, len);
        roffset += len;
    }

    inline char Seek(){
        return roffset >= size ? EOF : buffer[roffset];
    }

    int Tell(){
        return roffset;
    }

    void SeekTo(int pos){
        roffset = pos;
    }

    int GetSize(){
        return size;
    }

    jbyte ReadByte(){
        if(roffset >= offset)
            return EOF;
        return buffer[roffset++];
    }

    inline char ReadChar(){
        if(roffset >= offset)
            return EOF;
        return buffer[roffset++];
    }

    void ReadSwap(void* buf, int len){
        Update(roffset + len - offset);
        for(int i = 0; i < len; i++){
            ((char*)buf)[len - i - 1] = buffer[roffset++];
        }
    }

    short ReadShortSwap(){
        Update(roffset + 2 - offset);
        return (((short)buffer[roffset++]) << 8) | ((short)buffer[roffset++]);
    }

    int ReadIntSwap(){
        Update(roffset + 4 - offset);
        return (((int)buffer[roffset++]) << 24) | (((int)buffer[roffset++]) << 16) | (((int)buffer[roffset++]) << 8) | ((int)buffer[roffset++]);
    }

    void ReadFrom(FILE* f){
        debug_printf(("FileBuffer::ReadFrom 0x%p\n", f));
        size_t len;
        fseek(f, 0, std::ios::end);
        len = ftell(f);
        fseek(f, 0, std::ios::beg);
        Update(len);
        fread(buffer + offset, len, 1, f);
        offset += len;
    }

    void ReadFrom(const char* name){
        debug_printf(("FileBuffer::ReadFrom %s\n", name));
        FILE* f = fopen(name, "rb");
        size_t len;
        fseek(f, 0, std::ios::end);
        len = ftell(f);
        fseek(f, 0, std::ios::beg);
        Update(len);
        fread(buffer + offset, len, 1, f);
        offset += len;
        fclose(f);
    }

    void ReadFrom(const std::vector<jbyte>& vec){
        Update(vec.size());
        memcpy(buffer + offset, vec.data(), vec.size());
        offset += vec.size();
    }
};

class Serializable {
public:
    virtual void Serialize(FileBuffer& buffer) const = 0;
};

class Deserializable {
public:
    virtual void Deserialize(FileBuffer& buffer) = 0;
};

template <typename T>
class Array {
private:
    T* data;
    int size;
    int offset;

    void alloc(){
        T* New = new T[size << 1];
        memcpy(New, data, size * sizeof(T));
        size <<= 1;
        free(data);
        data = New;
    }
public:
    Array(){
        size = 32;
        data = new T[size];
        offset = 0;
    }
    Array(int size){
        this->size = 32;
        while(this->size < size)
            this->size <<= 1;
        data = new T[this->size];
        offset = size;
    }
    ~Array(){
        free(data);
    }
    int length(){
        return offset;
    }
    T& operator[](int index){
        while(index >= size)
            alloc();
        if(index >= offset)
            offset = index + 1;
        return data[index];
    }
    void append(T val){
        this->operator[](length()) = val;
    }
    void forEach(void(*func)(T val)){
        for(int i = 0; i < offset; i++)
            func(data[i]);
    }
};

class Constant : Serializable, Deserializable {
private:
    int type;
    void* data;
    int len;
    int id;

    Constant(){}

public:
    int GetID(){
        return id;
    }

    ~Constant(){
        free(data);
    }

    virtual void Serialize(FileBuffer& buffer) const override {
        buffer.Write(&type, 1);
        if(type == CLASS_CONSTANT_UTF8){
            buffer.WriteShortSwap(len);
            buffer.Write(data, len);
        }else{
            buffer.WriteSwap(data, len);
        }
    }

    virtual void Deserialize(FileBuffer& buffer) override {
        if(data)
            free(data);
        type = buffer.ReadByte();
        switch(type){
        case CLASS_CONSTANT_UTF8:
            break;
        case CLASS_CONSTANT_INTEGER:
            break;
        case CLASS_CONSTANT_LONG:
            break;
        case CLASS_CONSTANT_FLOAT:
            break;
        case CLASS_CONSTANT_DOUBLE:
            break;
        case CLASS_CONSTANT_STRING:
            break;
        case CLASS_CONSTANT_NAME_AND_TYPE:
            break;
        case CLASS_CONSTANT_CLASS_REF:
            break;
        case CLASS_CONSTANT_FIELD_REF:
            break;
        case CLASS_CONSTANT_METHOD_REF:
            break;
        case CLASS_CONSTANT_INTERFACE_METHOD_REF:
            break;
        case CLASS_CONSTANT_METHOD_TYPE:
            break;
        case CLASS_CONSTANT_METHOD_HANDLE:
            break;
        case CLASS_CONSTANT_INVOKE_DYNAMIC:
            break;
        default:
            break;
        }
        return;
    }

    int GetType(){ return type; }

    const void* GetData(){ return data; }

    int GetLen(){ return len; }

    static Constant* Int(int v, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_INTEGER;
        ret->data = new int(v);
        ret->len = sizeof(int);
        return ret;
    }

    static Constant* Long(long long v, int& number){
        Constant* ret = new Constant();
        ret->id = number;
        number += 2;
        ret->type = CLASS_CONSTANT_LONG;
        ret->data = new long long(v);
        ret->len = sizeof(long long);
        return ret;
    }

    static Constant* Float(float v, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_FLOAT;
        ret->data = new float(v);
        ret->len = sizeof(float);
        return ret;
    }

    static Constant* Double(double v, int& number){
        Constant* ret = new Constant();
        ret->id = number;
        number += 2;
        ret->type = CLASS_CONSTANT_DOUBLE;
        ret->data = new double(v);
        ret->len = sizeof(double);
        return ret;
    }

    static Constant* String(std::string& v, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_UTF8;
        ret->len = v.length();
        ret->data = new char[v.length()];
        memcpy(ret->data, v.c_str(), v.length());
        return ret;
    }

    static Constant* StringRef(jindex sid, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_STRING;
        ret->len = 2;
        ret->data = new jindex(sid);
        return ret;
    }

    static Constant* ClassRef(jindex sid, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_CLASS_REF;
        ret->data = new jindex(sid);
        ret->len = sizeof(jindex);
        return ret;
    }

    static Constant* FieldRef(jindex cid, jindex ntid, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_FIELD_REF;
        ret->data = new jindex[]{ntid, cid};
        ret->len = 2 * sizeof(jindex);
        return ret;
    }

    static Constant* MethodRef(jindex cid, jindex ntid, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_METHOD_REF;
        ret->data = new jindex[]{ntid, cid};
        ret->len = 2 * sizeof(jindex);
        return ret;
    }

    static Constant* InterfaceMethodRef(jindex cid, jindex ntid, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_INTERFACE_METHOD_REF;
        ret->data = new jindex[]{ntid, cid};
        ret->len = 2 * sizeof(jindex);
        return ret;
    }

    static Constant* NameAndType(jindex nid, jindex tid, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_NAME_AND_TYPE;
        ret->data = new jindex[]{tid, nid};
        ret->len = 2 * sizeof(jindex);
        return ret;
    }

    static Constant* MethodHandle(jindex kid, jindex iid, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_METHOD_HANDLE;
        ret->data = new char[]{(char)(iid >> 8), (char)iid, (char)kid};
        ret->len = 3;
        return ret;
    }

    static Constant* MethodType(jindex sid, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_METHOD_TYPE;
        ret->data = new jindex(sid);
        ret->len = sizeof(jindex);
        return ret;
    }

    static Constant* InvokeDynamic(jindex maid, jindex ntid, int& number){
        Constant* ret = new Constant();
        ret->id = number++;
        ret->type = CLASS_CONSTANT_INVOKE_DYNAMIC;
        ret->data = new jindex[]{ntid, maid};
        ret->len = 2 * sizeof(jindex);
        return ret;
    }
};

template <typename T>
void free(std::vector<T*>& vec){
    for(int i = 0; i < vec.size(); i++)
        if(vec[i])
            delete vec[i];
}

void WriteBytes(std::vector<jbyte>& vec, const void* s, int len){
    for(int i = 0; i < len; i++)
        vec.push_back(((char*)s)[i]);
}

jindex SwapIndex(jindex v){
    return (v << 8) | (v >> 8);
}

template<typename... Args>
static std::string str_format(const std::string &format, Args... args){
	int size_buf = std::snprintf(NULL, 0, format.c_str(), args...) + 1; 
	char* buf = new(std::nothrow) char[size_buf];

	if (!buf)
		return std::string("");

	std::snprintf(buf, size_buf, format.c_str(), args...);
	std::string ret = std::string(buf, buf + size_buf - 1);
    delete[] buf;
    return ret;
}

template<typename... Args>
static std::wstring wstr_format(const std::wstring &format, Args... args){
	int size_buf = std::swprintf(NULL, 0, format.c_str(), args...) + 1; 
	wchar_t* buf = new(std::nothrow) wchar_t[size_buf];

	if (!buf)
		return std::wstring(L"");

	std::swprintf(buf, format.c_str(), args...);
	std::wstring ret = std::wstring(buf, buf + size_buf - 1);
    delete[] buf;
    return ret;
}

#pragma region attributes
#pragma pack(push, 1)

#define read_origin(b, l) buffer.Read(b, l)

#define read(x) buffer.ReadSwap(&x, sizeof(x))
#define read_vec(x, l) x.resize(l); for(int i = 0; i < l; i++) buffer.ReadSwap(&x[i], sizeof(x[i]))
#define read_vec_len(x) x.resize(buffer.ReadShortSwap()); for(int i = 0; i < x.size(); i++) buffer.ReadSwap(&x[i], sizeof(x[i]))

#define write_origin(b, l) buffer.Write(b, l)

#define write(x) buffer.WriteSwap(&x, sizeof(x))
#define write_vec(x) for(int i = 0; i < x.size(); i++) buffer.WriteSwap(&x[i], sizeof(x[i]))
#define write_attr(x) buffer.WriteShortSwap(x.size()); for(int i = 0; i < x.size(); i++) x[i]->Serialize(buffer)
#define write_attr_nonptr(x) buffer.WriteShortSwap(x.size()); for(int i = 0; i < x.size(); i++) x[i].Serialize(buffer)
#define write_vec_len(x) buffer.WriteShortSwap(x.size()); for(int i = 0; i < x.size(); i++) buffer.WriteSwap(&x[i], sizeof(x[i]))

class Attribute : Serializable {
public:
    jindex Name;

    virtual jlength GetLength() const = 0;

    virtual void Serialize(FileBuffer& buffer) const override {
        write(Name);
        buffer.WriteIntSwap(GetLength());
    }

    void Serialize(FileBuffer& buffer, jlength Length) const {
        write(Name);
        buffer.WriteIntSwap(Length);
    }
};

class AttributeCode : public Attribute {
public:
    jcount MaxStack;        //本地栈大小，push与pop指令最大栈高度
    jcount MaxLocals;       //总本地变量大小，包括参数。实例方法其引用在第0位置，再是参数、局部变量，long和double大小为2，其余都为1(注：参数或实例引用的索引为从0开始，局部变量在后面)
    std::vector<jbyte> Code;
    struct ExceptionInfo {
        jindex StartPC;
        jindex EndPC;
        jindex HandlePC;
        jindex CatchType;
    };
    std::vector<ExceptionInfo> ExceptionTable;
    std::vector<Attribute*> Attributes;

    virtual void Serialize(FileBuffer& buffer) const override {
        debug_printf(("AttributeCode::Serialize\n"));
        Attribute::Serialize(buffer);
        write(MaxStack);
        write(MaxLocals);
        buffer.WriteIntSwap(Code.size());
        write_origin(Code.data(), Code.size());
        buffer.WriteShortSwap(ExceptionTable.size());
        for(int i = 0; i < ExceptionTable.size(); i++){
            write(ExceptionTable[i].StartPC);
            write(ExceptionTable[i].EndPC);
            write(ExceptionTable[i].HandlePC);
            write(ExceptionTable[i].CatchType);
        }
        write_attr(Attributes);
    }

    virtual jlength GetLength() const override {
        jlength Length = 12 + Code.size() + (ExceptionTable.size() << 3);
        for(int i = 0; i < Attributes.size(); i++){
            Length += 6 + Attributes[i]->GetLength();
        }
        return Length;
    }
};

class AttributeLineNumberTable : public Attribute {
public:
    struct LineNumberInfo {
        jindex StartPC;
        jindex LineNumber;
    };
    std::vector<LineNumberInfo> LineNumberTable;

    virtual void Serialize(FileBuffer& buffer) const override {
        debug_printf(("AttributeLineNumberTable::Serialize\n"));
        Attribute::Serialize(buffer);
        buffer.WriteShortSwap(LineNumberTable.size());
        for(int i = 0; i < LineNumberTable.size(); i++){
            write(LineNumberTable[i].StartPC);
            write(LineNumberTable[i].LineNumber);
        }
    }

    virtual jlength GetLength() const override {
        return 2 + (LineNumberTable.size() << 2);
    }
};

class AttributeLocalVariableTable : public Attribute {
public:
    struct LocalVariableInfo {
        jindex StartPC;
        jcount Length;
        jindex NameIndex;
        jindex DescriptorIndex;
        jindex Index;
    };
    std::vector<LocalVariableInfo> LocalVariableTable;

    virtual void Serialize(FileBuffer& buffer) const override {
        debug_printf(("AttributeLocalVariableTable::Serialize\n"));
        Attribute::Serialize(buffer);
        buffer.WriteShortSwap(LocalVariableTable.size());
        for(int i = 0; i < LocalVariableTable.size(); i++){
            write(LocalVariableTable[i].StartPC);
            write(LocalVariableTable[i].Length);
            write(LocalVariableTable[i].NameIndex);
            write(LocalVariableTable[i].DescriptorIndex);
            write(LocalVariableTable[i].Index);
        }
    }

    virtual jlength GetLength() const override {
        return 2 + (LocalVariableTable.size() * 10);
    }
};

class AttributeException : public Attribute {
public:
    std::vector<jindex> ExceptionClasses;

    virtual void Serialize(FileBuffer& buffer) const override {
        debug_printf(("AttributeException::Serialize\n"));
        Attribute::Serialize(buffer);
        write_vec_len(ExceptionClasses);
    }

    virtual jlength GetLength() const override {
        return (ExceptionClasses.size() + 1) << 1;
    }
};

class AttributeSignature : public Attribute {
public:
    jindex Signature;

    virtual void Serialize(FileBuffer& buffer) const override {
        debug_printf(("AttributeSignature::Serialize\n"));
        Attribute::Serialize(buffer);
        write(Signature);
    }

    virtual jlength GetLength() const override {
        return 2;   
    }
};

class AttributeSourceFile : public Attribute {
public:
    jindex SourceFile;

    virtual void Serialize(FileBuffer& buffer) const override {
        debug_printf(("AttributeSourceFile::Serialize\n"));
        Attribute::Serialize(buffer);
        write(SourceFile);
    }

    virtual jlength GetLength() const override {
        return 2;
    }
};

#pragma pack(pop)
#pragma endregion

class FieldAttribute : Serializable {
public:
    jflag AccessFlag;
    jindex Name;
    jindex Descriptor;
    std::vector<Attribute*> AttributeTable;

    FieldAttribute(){}

    ~FieldAttribute(){
        free(AttributeTable);
    }

    virtual void Serialize(FileBuffer& buffer) const override {
        debug_printf(("FieldAttribute::Serialize\n"));
        write(AccessFlag);
        write(Name);
        write(Descriptor);
        write_attr(AttributeTable);
    }
};

class MethodAttribute : Serializable {
public:
    jflag AccessFlag;
    jindex Name;
    jindex Descriptor;
    std::vector<Attribute*> AttributeTable;

    MethodAttribute(){}

    ~MethodAttribute(){
        free(AttributeTable);
    }

    virtual void Serialize(FileBuffer& buffer) const override {
        debug_printf(("MethodAttribute::Serialize\n"));
        write(AccessFlag);
        write(Name);
        write(Descriptor);
        write_attr(AttributeTable);
    }
};

class HashMap {
private:
    typedef unsigned char hash_t;

    struct Pair {
        Pair* Next;
        std::string String;
        jindex Index;

        Pair(std::string& s, jindex index){
            String = s;
            Index = index;
            Next = NULL;
        }
    };

    Pair* Table[256];

    hash_t Hash(std::string& s){
        hash_t ret = 0;
        for(size_t i = 0; i < s.length(); i++)
            ret = ret * 31 + s[i];
        return ret;
    }

    hash_t Hash(const void* s, size_t len){
        hash_t ret = 0;
        for(size_t i = 0; i < len; i++)
            ret = ret * 31 + ((const char*)s)[i];
        return ret;
    }

    void Delete(Pair* p){
        if(!p)
            return;
        Delete(p->Next);
        delete p;
    }
public:
    HashMap(){
        memset(Table, 0, sizeof(Table));
    }

    ~HashMap(){
        for(int i = 0; i < 256; i++)
            Delete(Table[i]);
    }

    jindex get(const char* str){
        std::string s(str);
        return get(s);
    }

    jindex get(std::string& s){
        Pair* Start = Table[Hash(s)];
        while(Start){
            if(Start->String == s)
                return Start->Index;
            Start = Start->Next;
        }
        return 0;
    }

    jindex get(const void* s, size_t len){
        Pair* Start = Table[Hash(s, len)];
        std::string Content((const char*)s, len);
        while(Start){
            if(Start->String == Content)
                return Start->Index;
            Start = Start->Next;
        }
        return 0;
    }

    jindex put(std::string& s, jindex index){
        Pair** Start = &Table[Hash(s)];
        while(*Start){
            if((*Start)->String == s)
                return (*Start)->Index;
            Start = &(*Start)->Next;
        }
        *Start = new Pair(s, index);
        return index;
    }

    jindex put(const void* s, size_t len, jindex index){
        Pair** Start = &Table[Hash(s, len)];
        std::string Content((const char*)s, len);
        while(*Start){
            if((*Start)->String == Content)
                return (*Start)->Index;
            Start = &(*Start)->Next;
        }
        *Start = new Pair(Content, index);
        return index;
    }
};

template <const unsigned int Size>
class SimpleMap {
private:
    void** Table;

    void* Alloc(){
        void* p = new void*[256];
        memset(p, 0, 256 * sizeof(void*));
        return p;
    }

    void Delete(void* p, int layer){
        if(!p)
            return;
        if(layer == Size){
            delete p;
            return;
        }
        for(int i = 0; i < 256; i++)
            Delete(((void**)p)[i], layer + 1);
        delete[] p;
    }
public:
    SimpleMap(){
        Table = NULL;
    }

    ~SimpleMap(){
        Delete(Table, 0);
    }

    jindex get(void* s){
        void** cur = &Table;
        for(int i = 0; i < Size; i++){
            if(!(*cur))
                *cur = Alloc();
            cur = (void**)*cur + ((const unsigned char*)s)[i];
        }
        return *cur == NULL ? 0 : *(jindex*)*cur;
    }

    jindex put(void* s, jindex index){
        void** cur = &Table;
        for(int i = 0; i < Size; i++){
            if(!(*cur))
                *cur = Alloc();
            cur = (void**)*cur + ((const unsigned char*)s)[i];
        }
        if(!(*cur))
            *cur = (void*)new jindex(index);
        return *(jindex*)*cur;
    }
};

class JavaClass : Serializable, Deserializable {
public:
    jmagic Magic;
    jversion MinorVersion;
    jversion MajorVersion;
    std::vector<Constant*> ConstantTable;
    jflag AccessFlag;
    jindex ThisClass;
    jindex SuperClass;
    std::vector<jindex> Interfaces;
    std::vector<FieldAttribute*> FieldAttributes;
    std::vector<MethodAttribute*> MethodAttributes;
    std::vector<Attribute*> GlobalAttributes;

    int ConstantNumber;

    HashMap ConstantStringMap;
    HashMap ConstantIntMap;
    HashMap ConstantLongMap;
    HashMap ConstantFloatMap;
    HashMap ConstantDoubleMap;
    HashMap ConstantStringRefMap;
    HashMap ConstantClassRefMap;
    HashMap ConstantNameAndTypeMap;
    HashMap ConstantFieldRefMap;
    HashMap ConstantMethodRefMap;
    HashMap ConstantMethodTypeMap;
    HashMap ConstantMethodHandleMap;
    HashMap ConstantInterfaceMethodRefMap;
    HashMap ConstantInvokeDynamicMap;

    JavaClass(){
        Magic = CLASS_FILE_MAGIC;
        MinorVersion = 0;
        MajorVersion = 0x34;
        ConstantNumber = 1;
    }

    ~JavaClass(){
        free(ConstantTable);
        free(FieldAttributes);
        free(MethodAttributes);
        free(GlobalAttributes);
    }

    virtual void Serialize(FileBuffer& buffer) const override {
        debug_printf(("JavaClass::Serialize\n"));
        write(Magic);
        write(MinorVersion);
        write(MajorVersion);
        buffer.WriteShortSwap(ConstantTable.size() + 1);
        for(int i = 0; i < ConstantTable.size(); i++)
            ConstantTable[i]->Serialize(buffer);
        write(AccessFlag);
        write(ThisClass);
        write(SuperClass);
        write_vec_len(Interfaces);
        write_attr(FieldAttributes);
        write_attr(MethodAttributes);
        write_attr(GlobalAttributes);
    }

    size_t LookupConstant(jindex index){
        for(size_t i = index - 1; i >= 0; i--){
            if(ConstantTable[i]->GetID() == index)
                return i;
        }
        return -1;
    }

    virtual void Deserialize(FileBuffer& buffer) override {
        read(Magic);
        read(MinorVersion);
        read(MajorVersion);
    }

    void WriteToFile(const char* filename){
        FileBuffer buf;
        Serialize(buf);
        buf.WriteTo(filename);
    }

    inline jindex GetConstantCount(){
        return ConstantNumber - 1;
    }

    jindex PutString(const char* str){
        std::string s(str);
        return PutString(s);
    }

    jindex PutString(std::string& s){
        size_t size = ConstantStringMap.put(s, GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::String(s, ConstantNumber));
            debug_printf(("JavaClass::PutString %s return %hu\n", s.c_str(), GetConstantCount()));
            return GetConstantCount();
        }
        debug_printf(("JavaClass::PutString %s return %hu\n", s.c_str(), size + 1));
        return size + 1;
    }
    
    jindex PutInt(int v){
        size_t size = ConstantIntMap.put(&v, sizeof(v), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::Int(v, ConstantNumber));
            debug_printf(("JavaClass::PutInt %d return %hu\n", v, GetConstantCount()));
            return GetConstantCount();
        }
        debug_printf(("JavaClass::PutInt %d return %hu\n", v, size + 1));
        return size + 1;
    }

    jindex PutLong(long long v){
        size_t size = ConstantLongMap.put(&v, sizeof(v), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::Long(v, ConstantNumber));
            debug_printf(("JavaClass::PutLong %lld return %hu\n", v, GetConstantCount() - 1));
            return GetConstantCount() - 1;
        }
        debug_printf(("JavaClass::PutLong %lld return %hu\n", v, size + 1));
        return size + 1;
    }

    jindex PutFloat(float v){
        size_t size = ConstantFloatMap.put(&v, sizeof(v), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::Float(v, ConstantNumber));
            debug_printf(("JavaClass::PutFloat %f return %hu\n", v, GetConstantCount()));
            return GetConstantCount();
        }
        debug_printf(("JavaClass::PutFloat %f return %hu\n", v, size + 1));
        return size + 1;
    }

    jindex PutDouble(double v){
        size_t size = ConstantDoubleMap.put(&v, sizeof(v), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::Double(v, ConstantNumber));
            debug_printf(("JavaClass::PutDouble %lf return %hu\n", v, GetConstantCount() - 1));
            return GetConstantCount() - 1;
        }
        debug_printf(("JavaClass::PutDouble %lf return %hu\n", v, size + 1));
        return size + 1;
    }

    jindex PutStringRef(const char* str){
        std::string s(str);
        return PutStringRef(s);
    }

    jindex PutStringRef(std::string& s){
        return PutStringRef(PutString(s));
    }

    jindex PutStringRef(jindex v){
        size_t size = ConstantStringRefMap.put(&v, sizeof(v), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::StringRef(v, ConstantNumber));
            debug_printf(("JavaClass::PutStringRef %hu return %hu\n", v, GetConstantCount()));
            return GetConstantCount();
        }
        debug_printf(("JavaClass::PutStringRef %hu return %hu\n", v, size + 1));
        return size + 1;
    }

    jindex PutClassRef(const char* str){
        std::string s(str);
        return PutClassRef(s);
    }

    jindex PutClassRef(std::string& s){
        return PutClassRef(PutString(s));
    }

    jindex PutClassRef(jindex v){
        size_t size = ConstantClassRefMap.put(&v, sizeof(v), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::ClassRef(v, ConstantNumber));
            debug_printf(("JavaClass::PutClassRef %hu return %hu\n", v, GetConstantCount()));
            return GetConstantCount();
        }
        debug_printf(("JavaClass::PutClassRef %hu return %hu\n", v, size + 1));
        return size + 1;
    }

    jindex PutNameAndType(const char* name, const char* type){
        std::string n(name), t(type);
        return PutNameAndType(n, t);
    }

    jindex PutNameAndType(std::string& n, std::string& t){
        return PutNameAndType(PutString(n), PutString(t));
    }

    jindex PutNameAndType(jindex n, jindex t){
        jindex key[]{n, t};
        size_t size = ConstantNameAndTypeMap.put(key, sizeof(key), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::NameAndType(n, t, ConstantNumber));
            debug_printf(("JavaClass::PutNameAndType %hu %hu return %hu\n", n, t, GetConstantCount()));
            return GetConstantCount();
        }
        debug_printf(("JavaClass::PutNameAndType %hu %hu return %hu\n", n, t, size + 1));
        return size + 1;
    }

    jindex PutFieldRef(const char* clazz, const char* name, const char* type){
        std::string c(clazz), n(name), t(type);
        return PutFieldRef(c, n, t);
    }

    jindex PutFieldRef(std::string& c, std::string& n, std::string& t){
        return PutFieldRef(PutClassRef(c), PutNameAndType(n, t));
    }

    jindex PutFieldRef(jindex c, jindex nt){
        jindex key[]{c, nt};
        size_t size = ConstantFieldRefMap.put(key, sizeof(key), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::FieldRef(c, nt, ConstantNumber));
            debug_printf(("JavaClass::PutFieldRef %hu %hu return %hu\n", c, nt, GetConstantCount()));
            return GetConstantCount();
        }
        debug_printf(("JavaClass::PutFieldRef %hu %hu return %hu\n", c, nt, size + 1));
        return size + 1;
    }

    jindex PutMethodRef(const char* clazz, const char* name, const char* type){
        std::string c(clazz), n(name), t(type);
        return PutMethodRef(c, n, t);
    }

    jindex PutMethodRef(std::string& c, std::string& n, std::string& t){
        return PutMethodRef(PutClassRef(c), PutNameAndType(n, t));
    }

    jindex PutMethodRef(jindex c, jindex nt){
        jindex key[]{c, nt};
        size_t size = ConstantMethodRefMap.put(key, sizeof(key), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::MethodRef(c, nt, ConstantNumber));
            debug_printf(("JavaClass::PutMethodRef %hu %hu return %hu\n", c, nt, GetConstantCount()));
            return GetConstantCount();
        }
        debug_printf(("JavaClass::PutMethodRef %hu %hu return %hu\n", c, nt, size + 1));
        return size + 1;
    }

    jindex PutInterfaceMethodRef(const char* clazz, const char* name, const char* type){
        std::string c(clazz), n(name), t(type);
        return PutInterfaceMethodRef(c, n, t);
    }

    jindex PutInterfaceMethodRef(std::string& c, std::string& n, std::string& t){
        return PutInterfaceMethodRef(PutClassRef(c), PutNameAndType(n, t));
    }

    jindex PutInterfaceMethodRef(jindex c, jindex nt){
        jindex key[]{c, nt};
        size_t size = ConstantInterfaceMethodRefMap.put(key, sizeof(key), GetConstantCount());
        if(GetConstantCount() == size){
            ConstantTable.push_back(Constant::InterfaceMethodRef(c, nt, ConstantNumber));
            debug_printf(("JavaClass::PutInterfaceMethodRef %hu %hu return %hu\n", c, nt, GetConstantCount()));
            return GetConstantCount();
        }
        debug_printf(("JavaClass::PutInterfaceMethodRef %hu %hu return %hu\n", c, nt, size + 1));
        return size + 1;
    }

    jindex PutConstant(Constant* c){
        ConstantTable.push_back(c);
        return ConstantNumber - ((c->GetType() == CLASS_CONSTANT_LONG || c->GetType() == CLASS_CONSTANT_DOUBLE) ? 1 : 0);
    }

    Constant* LastConstant(){
        if(ConstantTable.empty())
            return NULL;
        return ConstantTable[ConstantTable.size() - 1];
    }
};

template <class B, class D>
class is_inherit {
public:
	constexpr bool result() const {
        return judge((D*)0);
    }
protected:
	constexpr bool judge(B* var) const {
        return true;
    }

	constexpr bool judge(void* var) const {
        return false;
    }
};

namespace Compiler {
    enum class StateCode {
        STATE_NULL = -2,
        STATE_EXIT = -1,
        STATE_ENTRY = 0,

        STATE_WORD_TYPE_NULL = 0,
        STATE_WORD_TYPE_NUMBER = 1,
        STATE_WORD_TYPE_LETTER= 2,
        STATE_WORD_TYPE_SIGN = 3,
        STATE_WORD_TYPE_SPACE = 4,
        STATE_WORD_TYPE_STRING = 5,
        STATE_WORD_TYPE_CHARACTER = 6,

        STATE_PACKAGE,
        STATE_PACKAGE_END,
        STATE_IMPORT,
        STATE_IMPORT_END,
        STATE_FLAG,
        STATE_CLASS,
        STATE_AFTER_CLASS,
        STATE_INTERFACE,
        STATE_ENUM,
        STATE_ANNOTATION,
        STATE_EXTENDS,
        STATE_IMPLEMENTS,
        STATE_IMPLEMENTS_AFTER,
        STATE_CHARACTER,//'x'
        STATE_STRING,//"x"
        STATE_SIGN,
        STATE_NUMBER,
        STATE_NAME,
        STATE_THIS,
        STATE_SUPER,
        STATE_VOID,
        STATE_INT,
        STATE_LONG,
        STATE_FLOAT,
        STATE_DOUBLE,
        STATE_CHAR,
        STATE_BYTE,
        STATE_SHORT,
        STATE_BOOLEAN,
        STATE_IF,
        STATE_ELSE,
        STATE_FOR,
        STATE_SWITCH,
        STATE_CASE,
        STATE_DEFAULT,
        STATE_BREAK,
        STATE_CONTINUE,
        STATE_RETURN,
    };

    class DispatchTarget {
    public:
        virtual ~DispatchTarget(){};
        virtual bool Dispatch(StateCode state, std::string& content) = 0;

        void* parent;
    };

    template <class T> class StateMachine;
    class WordFetcher;
    class JavaCompiler;

    template <class T>
    class StateMachine {
    private:
        std::vector<std::function<StateCode(T*)>> states;

    public:
        StateCode cur;
        std::vector<std::string> err;

        StateMachine(){}

        virtual ~StateMachine(){}

        void Resize(size_t size){
            size_t origin = states.size();
            if(size <= origin){
                states.resize(size);
                return;
            }
            states.resize(size);
            for(size_t i = origin; i < size; i++)
                states[i] = NULL;
        }

        void AddState(StateCode state, std::function<StateCode(T*)> action){
            if((size_t)state >= states.size())
                Resize((size_t)state + 10);
            states[(size_t)state] = action;
        }

        void Entry(StateCode init){
            cur = init;
        }

        StateCode Step(){
            if(((size_t)cur >= states.size()) || (!states[(size_t)cur]))
                return StateCode::STATE_NULL;
            cur = states[(size_t)cur]((T*)this);
            return cur;
        }

        bool Run(StateCode init){
            cur = init;
            return Run();
        }

        bool Run(){
            while(true){
                StateCode state = Step();
                if(state == StateCode::STATE_EXIT)
                    return true;
                if(state == StateCode::STATE_NULL)
                    return false;
            }
        }
    };

    class WordFetcher : public StateMachine<WordFetcher> {
    public:
        enum Types {
            TYPE_NULL = 0,
            TYPE_NUMBER = 1,
            TYPE_LETTER = 2,
            TYPE_SIGN = 3,
            TYPE_SPACE = 4,
            TYPE_STRING = 5,
            TYPE_CHARACTER = 6,
            TYPE_TRANSLATE = 7
        }types[256] = { TYPE_NULL };

        FileBuffer& buffer;
        std::string temp;

        DispatchTarget* compiler;

        WordFetcher(FileBuffer& buffer) : StateMachine(), buffer(buffer) {}

        virtual ~WordFetcher(){}

        void Set(const char* s, Types type){
            for(int i = 0;s[i]; i++)
                types[(unsigned char)s[i]] = type;
        }

        void Set(char c, Types type){
            types[(unsigned char)c] = type;
        }

        inline char Seek(){
            return buffer.Seek();
        }

        inline char Read(){
            return buffer.ReadChar();
        }

        inline Types Type(char c){
            return types[(unsigned char)c];
        }

        bool Run(StateCode init){
            cur = init;
            return Run();
        }

        bool Run(){
            while(true){
                if(buffer.Readable() <= 0)
                    return true;
                StateCode state = Step();
                if(state == StateCode::STATE_EXIT)
                    return true;
                if(state == StateCode::STATE_NULL)
                    return false;
            }
        }

        void Attach(DispatchTarget* compiler){
            this->compiler = compiler;
        }
    };

    class JavaCompiler : public StateMachine<JavaCompiler>, public DispatchTarget {
    public:
        enum Sign {
            SIGN_LEFT_S_BRACKET,//(
            SIGN_RIGHT_S_BRACKET,//)
            SIGN_LEFT_M_BRACKET,//[
            SIGN_RIGHT_M_BRACKET,//]
            SIGN_LEFT_B_BRACKET,//{
            SIGN_RIGHT_B_BRACKET,//}
            SIGN_MOV,//=
            SIGN_ADD,//+
            SIGN_SUB,//-
            SIGN_MUL,//'*'
            SIGN_DIV,// /
            SIGN_MOD,//%
            SIGN_AND,//&
            SIGN_OR,//|
            SIGN_XOR,//^
            SIGN_ADD_E,
            SIGN_SUB_E,
            SIGN_MUL_E,
            SIGN_DIV_E,
            SIGN_MOD_E,
            SIGN_AND_E,
            SIGN_OR_E,
            SIGN_XOR_E,
            SIGN_NOT,//~
            SIGN_LOGICAL_NOT,//'!'
            SIGN_DOT,//.
            SIGN_SELECT,//'?'
            SIGN_SELECT_DIV,//:
            SIGN_END,//;
            SIGN_EQUAL,
            SIGN_NO_EQUAL,
            SIGN_GREATER,
            SIGN_LESS,
            SIGN_GREATER_E,
            SIGN_LESS_E,
            SIGN_LOGICAL_AND,
            SIGN_LOGICAL_OR,
        };

        enum Flag {
            FLAG_PUBLIC = 0x0001,
            FLAG_DEFAULT = 0x0002,
        };

        static const std::map<std::string, Sign> signmap;
        static const std::map<std::string, StateCode> keyword;
        static const std::map<std::string, Flag> flags;
        static const std::map<std::string, StateCode> declare;

        std::string package;
        std::vector<std::string> imports;

        FileBuffer buffer;
        JavaClass* output;

        Sign sign;
        StateCode state;
        std::string temp;
        std::string classname;
        std::string extends;
        std::vector<std::string> implements;
        int tempflag;

        std::vector<std::string> err;

        DispatchTarget* subcompiler;

        JavaCompiler() : StateMachine() {
            output = new JavaClass();
            subcompiler = NULL;
        }

        JavaCompiler(const char* filename) : StateMachine() {
            buffer.ReadFrom(filename);
            output = new JavaClass();
            subcompiler = NULL;
        }

        virtual ~JavaCompiler() override {
            delete output;
            if(subcompiler)
                delete subcompiler;
        }

        void WriteTo(const char* filename){
            FileBuffer buf;
            output->Serialize(buf);
            buf.WriteTo(filename);
        }

        virtual bool Dispatch(StateCode state, std::string& content) override {
            if(subcompiler){
                if(!subcompiler->Dispatch(state, content)){
                    delete subcompiler;
                    subcompiler = NULL;
                }
                return true;
            }
            if(state == StateCode::STATE_SIGN){
                DispatchSign(content);
                return true;
            }
            temp = content;
            this->state = state;
            Step();
            return true;
        }

        void DispatchSign(std::string sign){
            //存在的符号: = + - * / % += -= *= /= %= ? : & | ^ ! ~ &= |= ^= ( ) [ ] { } < > <= >= == != && ||
            //满足: 两个字符的符号拆开后无意义
            if(sign.empty())
                return;
            std::string temp;
            std::map<std::string, Compiler::JavaCompiler::Sign>::const_iterator it;
            if(sign.length() >= 2){
                temp = sign.substr(0, 2);
                it = signmap.find(temp);
                if(it != signmap.end()){
                    this->sign = it->second;
                    this->temp = temp;
                    this->state = StateCode::STATE_SIGN;
                    Step();
                    DispatchSign(sign.substr(2));
                    return;
                }
            }
            temp = sign.substr(0, 1);
            it = signmap.find(temp);
            if(it != signmap.end()){
                this->sign = it->second;
                this->temp = temp;
                this->state = StateCode::STATE_SIGN;
                Step();
                DispatchSign(sign.substr(1));
                return;
            }
            err.push_back("Unrecognized Sign: " + sign + "\n");
        }

        void Attach(DispatchTarget* subcompiler){
            this->subcompiler = subcompiler;
            subcompiler->parent = (void*)this;
        }
    };

    const std::map<std::string, JavaCompiler::Sign> JavaCompiler::signmap = {{"=", SIGN_MOV}, {"+", SIGN_ADD}, {"-", SIGN_SUB}, {"*", SIGN_MUL}, {"/", SIGN_DIV}, {"%", SIGN_MOD}, {"?", SIGN_SELECT}, {":", SIGN_SELECT_DIV},
                    {"&", SIGN_AND}, {"|", SIGN_OR}, {"^", SIGN_XOR}, {"(", SIGN_LEFT_S_BRACKET}, {")", SIGN_RIGHT_S_BRACKET}, {"[", SIGN_LEFT_M_BRACKET}, {"]", SIGN_RIGHT_M_BRACKET}, {"{", SIGN_LEFT_B_BRACKET},
                    {"}", SIGN_RIGHT_B_BRACKET}, {"<", SIGN_LESS}, {">", SIGN_GREATER}, {"+=", SIGN_ADD_E}, {"-=", SIGN_SUB_E}, {"*=", SIGN_MUL_E}, {"/=", SIGN_DIV_E}, {"%=", SIGN_MOD_E}, {"&=", SIGN_AND_E},
                    {"|=", SIGN_OR_E}, {"^=", SIGN_XOR_E}, {"<=", SIGN_LESS_E}, {">=", SIGN_GREATER_E}, {"==", SIGN_EQUAL}, {"!=", SIGN_NO_EQUAL}, {"&&", SIGN_LOGICAL_AND}, {"||", SIGN_LOGICAL_OR}, {";", SIGN_END}};

    const std::map<std::string, StateCode> JavaCompiler::keyword = {{"package", StateCode::STATE_PACKAGE}, {"import", StateCode::STATE_IMPORT}};
    const std::map<std::string, JavaCompiler::Flag> JavaCompiler::flags = {{"public", FLAG_PUBLIC}, {"default", FLAG_DEFAULT}};
    const std::map<std::string, StateCode> JavaCompiler::declare = {{"class", StateCode::STATE_CLASS}};

    class JavaClassCompiler : public StateMachine<JavaClassCompiler>, public DispatchTarget {
    public:
        enum Flag {
            FLAG_PUBLIC = 0x0001,
            FLAG_PROTECTED = 0x0002,
            FLAG_PRIVATE = 0x0004,
            FLAG_STATIC = 0x0008,
        };

        JavaClassCompiler(){}

        virtual ~JavaClassCompiler(){}

        static const std::map<std::string, Flag> flags;
        static const std::map<std::string, StateCode> types;

        StateCode state;
        std::string temp;
        int tempflag;

        std::vector<std::string> err;

        JavaCompiler* parent;
        DispatchTarget* subcompiler;

        virtual bool Dispatch(StateCode state, std::string& content) override {
            debug_printf(("JavaClassCompiler [Dispatch]: %s\n", content.c_str()));
            if(subcompiler){
                if(!subcompiler->Dispatch(state, content)){
                    delete subcompiler;
                    subcompiler = NULL;
                }
                return true;
            }
            temp = content;
            this->state = state;
            Step();
            return true;
        }

        JavaCompiler* Get(){
            return (JavaCompiler*)DispatchTarget::parent;
        }
    };

    const std::map<std::string, JavaClassCompiler::Flag> JavaClassCompiler::flags = {{"public", FLAG_PUBLIC}, {"protected", FLAG_PROTECTED}, {"private", FLAG_PRIVATE}, {"static", FLAG_STATIC}};
    const std::map<std::string, StateCode> JavaClassCompiler::types = {{"int", StateCode::STATE_INT}, {"long", StateCode::STATE_LONG}, {"float", StateCode::STATE_FLOAT}, {"double", StateCode::STATE_DOUBLE}, {"byte", StateCode::STATE_BYTE},
                    {"char", StateCode::STATE_CHAR}, {"short", StateCode::STATE_SHORT}, {"boolean", StateCode::STATE_BOOLEAN}, {"void", StateCode::STATE_VOID}};

    class JavaInterfaceCompiler : StateMachine<JavaInterfaceCompiler> {};
    class JavaEnumCompiler : StateMachine<JavaEnumCompiler> {};
    class JavaAnnotationCompiler : StateMachine<JavaAnnotationCompiler> {};
    class JavaMethodCompiler : StateMachine<JavaMethodCompiler> {};
    class JavaIfCompiler : StateMachine<JavaIfCompiler> {};
    class JavaForCompiler : StateMachine<JavaForCompiler> {};
    class JavaSwitchCompiler : StateMachine<JavaSwitchCompiler> {};

    JavaClassCompiler* ClassCompiler(){
        JavaClassCompiler* compiler = new JavaClassCompiler();
        compiler->Entry(StateCode::STATE_ENTRY);
        compiler->AddState(StateCode::STATE_ENTRY, [](JavaClassCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_NAME){
                std::map<std::string, Compiler::StateCode>::const_iterator it = caller->types.find(caller->temp);
                if(it != caller->types.end()){
                    debug_printf(("JavaClassCompiler [Type]: %s\n", caller->temp.c_str()));
                    return it->second;
                }
                std::map<std::string, JavaClassCompiler::Flag>::const_iterator fit = caller->flags.find(caller->temp);
                if(fit != caller->flags.end()){
                    debug_printf(("JavaClassCompiler [Flag]: %s\n", caller->temp.c_str()));
                    caller->tempflag = (int)fit->second;
                    return StateCode::STATE_FLAG;
                }
                caller->err.push_back("Invalid Word: " + caller->temp);
                return StateCode::STATE_ENTRY;
            }else if(caller->state == StateCode::STATE_STRING){
                debug_printf(("JavaClassCompiler [String]: %s\n", caller->temp.c_str()));
            }else if(caller->state == StateCode::STATE_SIGN){
                debug_printf(("JavaClassCompiler [Sign]: %s\n", caller->temp.c_str()));
            }
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_FLAG, [](JavaClassCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_NAME){
                std::map<std::string, JavaClassCompiler::Flag>::const_iterator fit;
                std::map<std::string, Compiler::StateCode>::const_iterator it;
                fit = caller->flags.find(caller->temp);
                if(fit != caller->flags.end()){
                    debug_printf(("JavaClassCompiler [Flag]: %s\n", caller->temp.c_str()));
                    caller->tempflag |= (int)fit->second;
                    return StateCode::STATE_FLAG;
                }
                it = caller->types.find(caller->temp);
                if(it != caller->types.end()){
                    debug_printf(("JavaClassCompiler [Type]: %s\n", caller->temp.c_str()));
                    return it->second;
                }
            }
            caller->err.push_back("Expected Declaration Or Flag");
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_VOID, [](JavaClassCompiler* caller) -> StateCode {
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_INT, [](JavaClassCompiler* caller) -> StateCode {
            // JavaClass* clazz = caller->Get()->output;
            // clazz->PutFieldRef("Main", "test", "I");
            // FieldAttribute* attr = new FieldAttribute();
            // attr->AccessFlag = FIELD_ACC_PUBLIC | FIELD_ACC_STATIC;
            // attr->Name = clazz->PutString("test");
            // attr->Descriptor = clazz->PutString("I");
            // clazz->FieldAttributes.push_back(attr);
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_LONG, [](JavaClassCompiler* caller) -> StateCode {
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_FLOAT, [](JavaClassCompiler* caller) -> StateCode {
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_DOUBLE, [](JavaClassCompiler* caller) -> StateCode {
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_BYTE, [](JavaClassCompiler* caller) -> StateCode {
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_BOOLEAN, [](JavaClassCompiler* caller) -> StateCode {
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_CHAR, [](JavaClassCompiler* caller) -> StateCode {
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_SHORT, [](JavaClassCompiler* caller) -> StateCode {
            return StateCode::STATE_ENTRY;
        });
        return compiler;
    }

    void Compile(const char* filename, const char* output){
        JavaCompiler* compiler = new JavaCompiler(filename);
        WordFetcher* fetch = new WordFetcher(compiler->buffer);
        fetch->Attach(compiler);
        fetch->Set("0123456789", WordFetcher::TYPE_NUMBER);
        fetch->Set(".@$_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", WordFetcher::TYPE_LETTER);
        fetch->Set("+-*/%&|!^~?:,=<>[]{}();", WordFetcher::TYPE_SIGN);
        fetch->Set(" \t\r\n\b\0", WordFetcher::TYPE_SPACE);
        fetch->Set('\"', WordFetcher::TYPE_STRING);
        fetch->Set('\'', WordFetcher::TYPE_CHARACTER);
        fetch->Set('\\', WordFetcher::TYPE_TRANSLATE);
        fetch->AddState(StateCode::STATE_WORD_TYPE_SPACE, [](WordFetcher* caller) -> StateCode {
            caller->temp.clear();
            char c = caller->Read();
            WordFetcher::Types t = caller->Type(c);
            switch(t){
            case WordFetcher::TYPE_SPACE:
                return StateCode::STATE_WORD_TYPE_SPACE;
            case WordFetcher::TYPE_NUMBER:
            case WordFetcher::TYPE_LETTER:
            case WordFetcher::TYPE_SIGN:
                caller->temp += c;
                return (StateCode)t;
            case WordFetcher::TYPE_STRING:
            case WordFetcher::TYPE_CHARACTER:
                return (StateCode)t;
            case WordFetcher::TYPE_NULL:
            default:
                caller->err.push_back(str_format("Unrecognized Character: %c", c));
                return StateCode::STATE_WORD_TYPE_NULL;
            }
        });
        fetch->AddState(StateCode::STATE_WORD_TYPE_NULL, [](WordFetcher* caller) -> StateCode {
            caller->temp.clear();
            char c = caller->Read();
            WordFetcher::Types t = caller->Type(c);
            switch(t){
            case WordFetcher::TYPE_SPACE:
                return (StateCode)t;
            case WordFetcher::TYPE_NUMBER:
            case WordFetcher::TYPE_LETTER:
            case WordFetcher::TYPE_SIGN:
                caller->temp += c;
                return (StateCode)t;
            case WordFetcher::TYPE_STRING:
            case WordFetcher::TYPE_CHARACTER:
                return (StateCode)t;
            case WordFetcher::TYPE_NULL:
            default:
                if(caller->err.empty())
                    caller->err.push_back("Unrecognized Character: ");
                caller->err[caller->err.size() - 1] += c;
                return StateCode::STATE_WORD_TYPE_NULL;
            }
        });
        fetch->AddState(StateCode::STATE_WORD_TYPE_LETTER, [](WordFetcher* caller) -> StateCode {
            char c = caller->Read();
            WordFetcher::Types t = caller->Type(c);
            switch(t){
            case WordFetcher::TYPE_SPACE:
                caller->compiler->Dispatch(StateCode::STATE_NAME, caller->temp);
                return (StateCode)t;
            case WordFetcher::TYPE_NUMBER:
            case WordFetcher::TYPE_LETTER:
                caller->temp += c;
                return StateCode::STATE_WORD_TYPE_LETTER;
            case WordFetcher::TYPE_SIGN:
                caller->compiler->Dispatch(StateCode::STATE_NAME, caller->temp);
                caller->temp = c;
                return (StateCode)t;
            case WordFetcher::TYPE_STRING:
            case WordFetcher::TYPE_CHARACTER:
                caller->compiler->Dispatch(StateCode::STATE_NAME, caller->temp);
                caller->temp.clear();
                return (StateCode)t;
            case WordFetcher::TYPE_NULL:
            default:
                caller->compiler->Dispatch(StateCode::STATE_NAME, caller->temp);
                caller->err.push_back(str_format("Unrecognized Character: %c", c));
                return StateCode::STATE_WORD_TYPE_NULL;
            }
        });
        fetch->AddState(StateCode::STATE_WORD_TYPE_NUMBER, [](WordFetcher* caller) -> StateCode {
            char c = caller->Read();
            WordFetcher::Types t = caller->Type(c);
            switch(t){
            case WordFetcher::TYPE_SPACE:
                caller->compiler->Dispatch(StateCode::STATE_NUMBER, caller->temp);
                return (StateCode)t;
            case WordFetcher::TYPE_NUMBER:
            case WordFetcher::TYPE_LETTER:
                caller->temp += c;
                return StateCode::STATE_WORD_TYPE_NUMBER;
            case WordFetcher::TYPE_SIGN:
                caller->compiler->Dispatch(StateCode::STATE_NUMBER, caller->temp);
                caller->temp = c;
                return (StateCode)t;
            case WordFetcher::TYPE_STRING:
            case WordFetcher::TYPE_CHARACTER:
                caller->compiler->Dispatch(StateCode::STATE_NUMBER, caller->temp);
                caller->temp.clear();
                return (StateCode)t;
            case WordFetcher::TYPE_NULL:
            default:
                caller->compiler->Dispatch(StateCode::STATE_NUMBER, caller->temp);
                caller->err.push_back(str_format("Unrecognized Character: %c", c));
                return StateCode::STATE_WORD_TYPE_NULL;
            }
        });
        fetch->AddState(StateCode::STATE_WORD_TYPE_SIGN, [](WordFetcher* caller) -> StateCode {
            char c = caller->Read();
            WordFetcher::Types t = caller->Type(c);
            switch(t){
            case WordFetcher::TYPE_SPACE:
                caller->compiler->Dispatch(StateCode::STATE_SIGN, caller->temp);
                return (StateCode)t;
            case WordFetcher::TYPE_NUMBER:
                caller->compiler->Dispatch(StateCode::STATE_SIGN, caller->temp);
                caller->temp = c;
                return StateCode::STATE_WORD_TYPE_NUMBER;
            case WordFetcher::TYPE_LETTER:
                caller->compiler->Dispatch(StateCode::STATE_SIGN, caller->temp);
                caller->temp = c;
                return StateCode::STATE_WORD_TYPE_LETTER;
            case WordFetcher::TYPE_SIGN:
                caller->temp += c;
                return (StateCode)t;
            case WordFetcher::TYPE_STRING:
            case WordFetcher::TYPE_CHARACTER:
                caller->compiler->Dispatch(StateCode::STATE_SIGN, caller->temp);
                caller->temp.clear();
                return (StateCode)t;
            case WordFetcher::TYPE_NULL:
            default:
                caller->compiler->Dispatch(StateCode::STATE_SIGN, caller->temp);
                caller->err.push_back(str_format("Unrecognized Character: %c", c));
                return StateCode::STATE_WORD_TYPE_NULL;
            }
        });
        fetch->AddState(StateCode::STATE_WORD_TYPE_STRING, [](WordFetcher* caller) -> StateCode {
            char c = caller->Read();
            WordFetcher::Types t = caller->Type(c);
            switch(t){
            case WordFetcher::TYPE_TRANSLATE:
                c = caller->Read();
                switch(c){
                case 'a':
                    caller->temp += '\a';
                    break;
                case 'b':
                    caller->temp += '\b';
                    break;
                case 'f':
                    caller->temp += '\f';
                    break;
                case 'r':
                    caller->temp += '\r';
                    break;
                case 'n':
                    caller->temp += '\n';
                    break;
                case 't':
                    caller->temp += '\t';
                    break;
                case 'v':
                    caller->temp += '\v';
                    break;
                case '\\':
                    caller->temp += '\\';
                    break;
                case '\'':
                    caller->temp += '\'';
                    break;
                case '\"':
                    caller->temp += '\"';
                    break;
                case '?':
                    caller->temp += '?';
                    break;
                case '0':
                    caller->temp += '\0';
                    break;
                case 'x':{
                    char temp;
                    static char(*const fun)(char) = [](char c) -> char {
                        if(c >= '0' && c <= '9')
                            return c - '0';
                        if(c >= 'A' && c <= 'F')
                            return c - 'A' + 10;
                        if(c >= 'a' && c <= 'f')
                            return c - 'a' + 10;
                        return EOF;
                    };
                    char val = fun(caller->Seek());
                    if(val != EOF){
                        temp = val;
                        caller->Read();
                    }else{
                        caller->err.push_back("\\x Has No Hexadecimal Number Following");
                        break;
                    }
                    val = fun(caller->Seek());
                    if(val != EOF){
                        temp = (temp << 4) | val;
                        caller->Read();
                    }
                    caller->temp += temp;
                }
                    break;
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':{
                    char temp = c;
                    if(caller->Seek() >= '0' && caller->Seek() <= '7')
                        temp = (temp << 3) | (caller->Read() - '0');
                    else{
                        caller->temp += temp;
                        break;
                    }
                    if(caller->Seek() >= '0' && caller->Seek() <= '7')
                        temp = (temp << 3) | (caller->Read() - '0');
                    caller->temp += temp;
                }
                    break;
                default:
                    caller->err.push_back(str_format("Unrecognized Translation Sign: %c", c));
                    break;
                }
                return StateCode::STATE_WORD_TYPE_STRING;
            case WordFetcher::TYPE_STRING:
                caller->compiler->Dispatch(StateCode::STATE_STRING, caller->temp);
                return StateCode::STATE_WORD_TYPE_SPACE;
            default:
                caller->temp += c;
                return StateCode::STATE_WORD_TYPE_STRING;
            }
        });
        fetch->AddState(StateCode::STATE_WORD_TYPE_CHARACTER, [](WordFetcher* caller) -> StateCode {
            char c = caller->Read();
            WordFetcher::Types t = caller->Type(c);
            switch(t){
            case WordFetcher::TYPE_TRANSLATE:
                c = caller->Read();
                switch(c){
                case 'a':
                    caller->temp += '\a';
                    break;
                case 'b':
                    caller->temp += '\b';
                    break;
                case 'f':
                    caller->temp += '\f';
                    break;
                case 'r':
                    caller->temp += '\r';
                    break;
                case 'n':
                    caller->temp += '\n';
                    break;
                case 't':
                    caller->temp += '\t';
                    break;
                case 'v':
                    caller->temp += '\v';
                    break;
                case '\\':
                    caller->temp += '\\';
                    break;
                case '\'':
                    caller->temp += '\'';
                    break;
                case '\"':
                    caller->temp += '\"';
                    break;
                case '?':
                    caller->temp += '?';
                    break;
                case '0':
                    caller->temp += '\0';
                    break;
                case 'x':{
                    char temp;
                    static char(*const fun)(char) = [](char c) -> char {
                        if(c >= '0' && c <= '9')
                            return c - '0';
                        if(c >= 'A' && c <= 'F')
                            return c - 'A' + 10;
                        if(c >= 'a' && c <= 'f')
                            return c - 'a' + 10;
                        return EOF;
                    };
                    char val = fun(caller->Seek());
                    if(val != EOF){
                        temp = val;
                        caller->Read();
                    }else{
                        caller->err.push_back("\\x Has No Hexadecimal Number Following");
                        break;
                    }
                    val = fun(caller->Seek());
                    if(val != EOF){
                        temp = (temp << 4) | val;
                        caller->Read();
                    }
                    caller->temp += temp;
                }
                    break;
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':{
                    char temp = c;
                    if(caller->Seek() >= '0' && caller->Seek() <= '7')
                        temp = (temp << 3) | (caller->Read() - '0');
                    else{
                        caller->temp += temp;
                        break;
                    }
                    if(caller->Seek() >= '0' && caller->Seek() <= '7')
                        temp = (temp << 3) | (caller->Read() - '0');
                    caller->temp += temp;
                }
                    break;
                default:
                    caller->err.push_back(str_format("Unrecognized Translation Sign: %c", c));
                    break;
                }
                return StateCode::STATE_WORD_TYPE_CHARACTER;
            case WordFetcher::TYPE_CHARACTER:
                caller->compiler->Dispatch(StateCode::STATE_CHARACTER, caller->temp);
                return StateCode::STATE_WORD_TYPE_SPACE;
            default:
                caller->temp += c;
                return StateCode::STATE_WORD_TYPE_CHARACTER;
            }
        });
        compiler->Entry(StateCode::STATE_ENTRY);
        compiler->AddState(StateCode::STATE_ENTRY, [](JavaCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_NAME){
                std::map<std::string, Compiler::StateCode>::const_iterator it = caller->keyword.find(caller->temp);
                if(it != caller->keyword.end()){
                    debug_printf(("JavaCompiler [Keyword]: %s\n", caller->temp.c_str()));
                    return it->second;
                }
                it = caller->declare.find(caller->temp);
                if(it != caller->declare.end()){
                    debug_printf(("JavaCompiler [Declare]: %s\n", caller->temp.c_str()));
                    return it->second;
                }
                std::map<std::string, JavaCompiler::Flag>::const_iterator fit = caller->flags.find(caller->temp);
                if(fit != caller->flags.end()){
                    debug_printf(("JavaCompiler [Flag]: %s\n", caller->temp.c_str()));
                    caller->tempflag = (int)fit->second;
                    return StateCode::STATE_FLAG;
                }
                caller->err.push_back("Invalid Word: " + caller->temp);
                return StateCode::STATE_ENTRY;
            }else if(caller->state == StateCode::STATE_STRING){
                debug_printf(("JavaCompiler [String]: %s\n", caller->temp.c_str()));
            }else if(caller->state == StateCode::STATE_SIGN){
                debug_printf(("JavaCompiler [Sign]: %s\n", caller->temp.c_str()));
            }
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_PACKAGE, [](JavaCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_NAME){
                debug_printf(("JavaCompiler [Package]: %s\n", caller->temp.c_str()));
                if(!caller->package.empty()){
                    caller->err.push_back("You Are Already Declared Package");
                }else caller->package = caller->temp;
                return StateCode::STATE_PACKAGE_END;
            }
            caller->err.push_back("Unknown Package Statement");
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_PACKAGE_END, [](JavaCompiler* caller) -> StateCode {
            if(caller->state != StateCode::STATE_SIGN || caller->temp != ";"){
                caller->err.push_back("Expected ';'");
            }
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_IMPORT, [](JavaCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_NAME){
                debug_printf(("JavaCompiler [Import]: %s\n", caller->temp.c_str()));
                caller->imports.push_back(caller->temp);
                return StateCode::STATE_IMPORT_END;
            }
            caller->err.push_back("Unknown Import Statement");
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_IMPORT_END, [](JavaCompiler* caller) -> StateCode {
            if(caller->state != StateCode::STATE_SIGN || caller->temp != ";"){
                caller->err.push_back("Expected ';'");
            }
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_FLAG, [](JavaCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_NAME){
                std::map<std::string, JavaCompiler::Flag>::const_iterator fit;
                std::map<std::string, Compiler::StateCode>::const_iterator it;
                fit = caller->flags.find(caller->temp);
                if(fit != caller->flags.end()){
                    debug_printf(("JavaCompiler [Flag]: %s\n", caller->temp.c_str()));
                    caller->tempflag |= (int)fit->second;
                    return StateCode::STATE_FLAG;
                }
                it = caller->declare.find(caller->temp);
                if(it != caller->declare.end()){
                    debug_printf(("JavaCompiler [Declare]: %s\n", caller->temp.c_str()));
                    return it->second;
                }
            }
            caller->err.push_back("Expected Declaration Or Flag");
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_CLASS, [](JavaCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_NAME){
                debug_printf(("JavaCompiler [ClassName]: %s\n", caller->temp.c_str()));
                caller->classname = caller->temp;
                return StateCode::STATE_AFTER_CLASS;
            }else{
                caller->err.push_back("Expected Class Name");
            }
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_AFTER_CLASS, [](JavaCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_SIGN && caller->temp == "{"){
                debug_printf(("JavaCompiler [ClassEntry]\n"));
                caller->Attach(ClassCompiler());
                return StateCode::STATE_ENTRY;
            }
            if(caller->state == StateCode::STATE_NAME){
                if(caller->temp == "extends"){
                    return StateCode::STATE_EXTENDS;
                }else if(caller->temp == "implements"){
                    return StateCode::STATE_IMPLEMENTS;
                }
            }
            caller->err.push_back("Expected '{' After Class Declaration");
            return StateCode::STATE_ENTRY;
        });
        compiler->AddState(StateCode::STATE_EXTENDS, [](JavaCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_NAME){
                caller->extends = caller->temp;
                return StateCode::STATE_AFTER_CLASS;
            }
            caller->err.push_back("Expected Class Name After Extends");
            return StateCode::STATE_AFTER_CLASS;
        });
        compiler->AddState(StateCode::STATE_IMPLEMENTS, [](JavaCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_NAME){
                caller->implements.push_back(caller->temp);
                return StateCode::STATE_IMPLEMENTS_AFTER;
            }
            caller->err.push_back("Expected Interface Name After Extends");
            return StateCode::STATE_AFTER_CLASS;
        });
        compiler->AddState(StateCode::STATE_IMPLEMENTS_AFTER, [](JavaCompiler* caller) -> StateCode {
            if(caller->state == StateCode::STATE_SIGN){
                if(caller->temp == "{"){
                    debug_printf(("JavaCompiler [ClassEntry]\n"));
                    caller->Attach(ClassCompiler());
                    return StateCode::STATE_ENTRY;
                }else if(caller->temp == ","){
                    return StateCode::STATE_IMPLEMENTS;
                }
            }
            caller->err.push_back("Expected '{' After Class Declaration");
            return StateCode::STATE_ENTRY;
        });
        fetch->Run(StateCode::STATE_WORD_TYPE_SPACE);
        for(int i = 0; i < fetch->err.size(); i++)
            debug_printf(("[ERROR] %s\n", fetch->err[i].c_str()));
        for(int i = 0; i < compiler->err.size(); i++)
            debug_printf(("[ERROR] %s\n", compiler->err[i].c_str()));
        compiler->WriteTo(output);
        delete fetch;
        delete compiler;
    }
}

void PutFields(JavaClass* main){
    {
        FieldAttribute* f = new FieldAttribute();
        f->Name = main->PutString("a");
        f->AccessFlag = FIELD_ACC_PRIVATE | FIELD_ACC_STATIC;
        f->Descriptor = main->PutString("I");
        main->FieldAttributes.push_back(f);
    }
    {
        FieldAttribute* f = new FieldAttribute();
        f->Name = main->PutString("a");
        f->AccessFlag = FIELD_ACC_PRIVATE | FIELD_ACC_STATIC;
        f->Descriptor = main->PutString("J");
        main->FieldAttributes.push_back(f);
    }
    {
        FieldAttribute* f = new FieldAttribute();
        f->Name = main->PutString("a");
        f->AccessFlag = FIELD_ACC_PRIVATE | FIELD_ACC_STATIC;
        f->Descriptor = main->PutString("Z");
        main->FieldAttributes.push_back(f);
    }
    {
        FieldAttribute* f = new FieldAttribute();
        f->Name = main->PutString("a");
        f->AccessFlag = FIELD_ACC_PRIVATE | FIELD_ACC_STATIC;
        f->Descriptor = main->PutString("B");
        main->FieldAttributes.push_back(f);
    }
    {
        FieldAttribute* f = new FieldAttribute();
        f->Name = main->PutString("a");
        f->AccessFlag = FIELD_ACC_PRIVATE | FIELD_ACC_STATIC;
        f->Descriptor = main->PutString("C");
        main->FieldAttributes.push_back(f);
    }
    {
        FieldAttribute* f = new FieldAttribute();
        f->Name = main->PutString("a");
        f->AccessFlag = FIELD_ACC_PRIVATE | FIELD_ACC_STATIC;
        f->Descriptor = main->PutString("S");
        main->FieldAttributes.push_back(f);
    }
    {
        FieldAttribute* f = new FieldAttribute();
        f->Name = main->PutString("a");
        f->AccessFlag = FIELD_ACC_PRIVATE | FIELD_ACC_STATIC;
        f->Descriptor = main->PutString("F");
        main->FieldAttributes.push_back(f);
    }
    {
        FieldAttribute* f = new FieldAttribute();
        f->Name = main->PutString("a");
        f->AccessFlag = FIELD_ACC_PRIVATE | FIELD_ACC_STATIC;
        f->Descriptor = main->PutString("D");
        main->FieldAttributes.push_back(f);
    }
    {
        FieldAttribute* f = new FieldAttribute();
        f->Name = main->PutString("a");
        f->AccessFlag = FIELD_ACC_PRIVATE | FIELD_ACC_STATIC;
        f->Descriptor = main->PutString("Ljava/lang/String;");
        main->FieldAttributes.push_back(f);
    }
}

void JavaPrintString(FileBuffer& bytes, JavaClass* clazz, const char* s){
    bytes.Write(Code::getstatic);
    bytes.WriteShortSwap(clazz->PutFieldRef("java/lang/System", "out", "Ljava/io/PrintStream;"));
    bytes.Write(Code::ldc);
    bytes.Write(clazz->PutStringRef(s));
    bytes.Write(Code::invokevirtual);
    bytes.WriteShortSwap(clazz->PutMethodRef("java/io/PrintStream", "println", "(Ljava/lang/String;)V"));
}

void JavaPrintStatic(FileBuffer& bytes, JavaClass* clazz, jindex field, const char* sig){
    bytes.Write(Code::getstatic);
    bytes.WriteShortSwap(clazz->PutFieldRef("java/lang/System", "out", "Ljava/io/PrintStream;"));
    bytes.Write(Code::getstatic);
    bytes.WriteShortSwap(field);
    bytes.Write(Code::invokevirtual);
    bytes.WriteShortSwap(clazz->PutMethodRef("java/io/PrintStream", "println", sig));
}

void PutMethods(JavaClass* cmain){
    {
        MethodAttribute* method = new MethodAttribute();
        AttributeCode* code = new AttributeCode();
        AttributeLineNumberTable* lines = new AttributeLineNumberTable();
        FileBuffer bytes;
        method->AccessFlag = METHOD_ACC_PUBLIC | METHOD_ACC_STATIC;
        method->Name = cmain->PutString("<clinit>");
        method->Descriptor = cmain->PutString("()V");
        code->Name = cmain->PutString("Code");
        code->MaxStack = 0;
        code->MaxLocals = 0;
        bytes.Write(Code::return_);
        bytes.WriteTo(code->Code);
        method->AttributeTable.push_back(code);
        cmain->MethodAttributes.push_back(method);
    }
    {
        MethodAttribute* method = new MethodAttribute();
        AttributeCode* code = new AttributeCode();
        AttributeLineNumberTable* lines = new AttributeLineNumberTable();
        FileBuffer bytes;
        method->AccessFlag = METHOD_ACC_PUBLIC;
        method->Name = cmain->PutString("<init>");
        method->Descriptor = cmain->PutString("()V");
        code->Name = cmain->PutString("Code");
        code->MaxStack = 1;
        code->MaxLocals = 1;
        bytes.Write(Code::aload_0);
        bytes.Write(Code::invokespecial);
        bytes.WriteShortSwap(cmain->PutMethodRef("java/lang/Object", "<init>", "()V"));
        bytes.Write(Code::return_);
        bytes.WriteTo(code->Code);
        method->AttributeTable.push_back(code);
        cmain->MethodAttributes.push_back(method);
    }
    {
        MethodAttribute* method = new MethodAttribute();
        AttributeCode* code = new AttributeCode();
        AttributeLineNumberTable* lines = new AttributeLineNumberTable();
        FileBuffer bytes;
        method->AccessFlag = METHOD_ACC_PUBLIC | METHOD_ACC_STATIC;
        method->Name = cmain->PutString("main");
        method->Descriptor = cmain->PutString("([Ljava/lang/String;)V");
        code->Name = cmain->PutString("Code");
        code->MaxStack = 2;
        code->MaxLocals = 1;
        JavaPrintString(bytes, cmain, "huzpsbakioi");
        JavaPrintStatic(bytes, cmain, cmain->PutFieldRef("Main", "a", "Ljava/lang/String;"), "(Ljava/lang/String;)V");
        bytes.Write(Code::return_);
        bytes.WriteTo(code->Code);
        method->AttributeTable.push_back(code);
        cmain->MethodAttributes.push_back(method);
    }
}

void PutGlobalAttributes(JavaClass* main){
    AttributeSourceFile* attr = new AttributeSourceFile();
    attr->Name = main->PutString("SourceFile");
    attr->SourceFile = main->PutString("Main.java");
    main->GlobalAttributes.push_back(attr);
}

int main(int argc, char** argv){
    // JavaClass* main = new JavaClass();
    // main->AccessFlag = CLASS_ACC_PUBLIC | CLASS_ACC_SUPER;
    // main->ThisClass = main->PutClassRef("Main");
    // main->SuperClass = main->PutClassRef("java/lang/Object");
    // PutFields(main);
    // PutMethods(main);
    // PutGlobalAttributes(main);
    // main->WriteToFile("Main.class");
    // delete main;
    Compiler::Compile("Main.java", "a.class");
    return 0;
}
