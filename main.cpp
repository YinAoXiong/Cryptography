#include <iostream>
#include "AES.h"

using namespace std;

int main() {
    byte plain[16] = {0x32, 0x88, 0x31, 0xe0,
                      0x43, 0x5a, 0x31, 0x37,
                      0xf6, 0x30, 0x98, 0x07,
                      0xa8, 0x8d, 0xa2, 0x34};
    AES test;
    //test.setKey();
    cout << "Key is:";
    for (int i = 0; i < 16; ++i) {
        cout << hex << test.getKet()[i].to_ulong() << " ";
    }
    cout << endl;

    cout<<endl<<"待加密的明文:"<<endl;
    for(int i=0;i<16;++i)
    {
        cout<<hex<<plain[i].to_ulong()<<" ";
        if((i+1)%4==0)
            cout<<endl;
    }
    cout<<endl;
    test.encrypt(plain);
    cout<<"加密后的密文："<<endl;
    for (int i = 0; i < 16; ++i) {
        cout << hex << plain[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;

    // 解密，输出明文
    test.decrypt(plain);
    cout << "解密后的明文："<<endl;
    for(int i=0; i<16; ++i)
    {
        cout << hex << plain[i].to_ulong() << " ";
        if((i+1)%4 == 0)
            cout << endl;
    }
    cout << endl;
    return 0;
}