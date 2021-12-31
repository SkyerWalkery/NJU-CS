#pragma once
const int DEAL_TIME_LEN = 10;


class Order {
public:
	Order(const int _id, const int _goods_id, const int _seller_id, const int _buyer_id, const double _amount, const char* _dealtime);
	Order();


	int id; //����ID,6���ַ�����ͷ�ַ�Ϊ��д��ĸT����5λΪ����
	int goods_id; //��ƷID,6���ַ�����ͷ�ַ�Ϊ��д��ĸM����5λΪ����
	int seller_id; //����ID,6���ַ�����ͷ�ַ�Ϊ��д��ĸU����5λΪ����
	int buyer_id; //���ID,6���ַ�����ͷ�ַ�Ϊ��д��ĸU����5λΪ����
	double amount; //���׽��,�������С������ȷ��С�����һλ
	char dealtime[DEAL_TIME_LEN + 1];//����ʱ��yyyy-mm-dd

};
