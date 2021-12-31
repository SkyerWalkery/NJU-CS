#pragma once
const int USER_NAME_LEN = 15;
const int USER_PASS_LEN = 20;
const int USER_CONTACT = 20;
const int USER_ADD_LEN = 20;
enum Identity{NORMAL, ADMINIS, FROZEN};//FROZEN���û�������Ա����


class User{
public:
	User(const int _id, const char* _name, const char* _password, const char* _contact, const char* _address, const double _money, const int _credit, Identity _identity);
	User();


	int id;//6���ַ�����ͷ�ַ�Ϊ��д��ĸU����5λΪ���֣��˴�ʡ��U
	char name[USER_NAME_LEN+1];//�û�����������10���ַ������ĺ��ֻ�Ӣ����ĸ
	char password[USER_PASS_LEN+1];//���룬������20���ַ���ֻ��Сд��ĸ���������
	char contact[USER_CONTACT+1];//��ϵ��ʽ��������20���ַ������������
	char address[USER_ADD_LEN+1]; //��ַ��������20���ַ������ĺ��ֻ�Ӣ����ĸ
	double money;//������һλС��
	int credit;//���÷�
	Identity identity;
};