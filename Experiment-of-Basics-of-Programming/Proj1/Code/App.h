#pragma once
#include<iostream>
#include<vector>
#include<cstdio>
#include<iomanip>
#include<string>
#include<fstream>
using namespace std;
#include "User.h"
#include "Goods.h"
#include "Order.h"
#include "Other.h"
#include "Mail.h"


enum AppState{DEFAULT, USER_MAIN, ADMINIS_MAIN, USER_FROZEN, USER_SELL, USER_SELL_GOODS, USER_SELL_GOODS_MANAG, USER_BUY, USER_BUY_DIREC, USER_INFO, MAIL, MAIL_INBOX};
/*

*/


class Application {
	vector<User> users;//�����û���Ϣ����
	vector<Goods> goodss;//������Ʒ��Ϣ����
	vector<Order> orders;//���ж�����Ϣ����
	vector<Mail> mails;//�����ʼ�����
	int users_num;//�û�����
	int goodss_num;//��Ʒ����
	int orders_num;//��������
	AppState appstate;
	vector<User>::iterator user_on;//ָ��ǰ��¼���û�
	vector<User>::iterator user_off;//ָ��ǰ����Ա��ͼ�������û�
	vector<Goods>::iterator goods_on;//ָ��ǰ��������Ʒ
	vector<Mail>::iterator mail_on;
public:
	Application();
	void Save();
	void Window(int option);
	void Start();
	void SignUp();
	void Login(int option);//��¼,0Ϊ������¼,1Ϊ��������
	void Buy();
	void Release();//������Ʒ
	void CheckGoodss(int option);//�鿴��Ʒ,0Ϊȫ����Ʒ,1Ϊ������Ʒ,2Ϊ�ϼܵĵ���Ʒ
	void CheckOrders(int option);//�鿴����,0Ϊȫ��,1Ϊ���,2Ϊ����
	void CheckUsers(int option);//�鿴�û�,0Ϊȫ��,1Ϊ�Լ�
	void CheckMails(int option);//�鿴�ʼ�,0Ϊȫ��,1Ϊ�ռ��˵�,2Ϊ�����˵�
	void GoodsManag(int option);//�޸���Ʒ��Ϣ
	void UserManag(int option);//�޸��û���Ϣ
	void MailManag(int option);//�����ʼ�,0Ϊ�Ѷ�����,1Ϊ�Ѷ�ָ��
	void BindGoods();//�󶨲�����Ʒ
	void BindUserOff();//�󶨹���Ա�������û�
	void BindMail();//�󶨲����ʼ�
	void TopUp();//��ֵ
	void SearchGoods();//������Ʒ
	void NewMail();//д�ʼ�
	int CheckPass(const char* cstr);//������밲ȫ�ԣ������������
	void CloseAcc();//ע���˺�
	void Notify(int option, int id);//֪ͨ
	
	
};