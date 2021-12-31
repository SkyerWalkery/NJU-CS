#pragma once
const int GOODS_NAME_LEN = 15;
const int ARRIVE_TIME_LEN = 10;
const int GOODS_DESCRIP_LEN = 100;
enum GoodState{SOLDOUT, WITHDRAWN, AVAILABLE};


class Goods {
public:
	Goods(const int _id, const char* _name, const double _price, const int _seller_id, const int _seller_credit, const char* _arrivetime, const char* _descrip, GoodState _state);
	Goods();


	int id;//6���ַ�����ͷ�ַ�Ϊ��д��ĸM����5λΪ���֣��˴�ʡ��M
	char name[GOODS_NAME_LEN+1];//��Ʒ����������10���ַ������ĺ��ֻ�Ӣ����ĸ
	double price; //�۸񣬴������С������ȷ��С�����һλ
	int seller_id;//����ID��6���ַ�����ͷ�ַ�Ϊ��д��ĸU����5λΪ����
	int seller_credit;//�������÷�
	char arrivetime[ARRIVE_TIME_LEN+1];//�ϼ�ʱ��yyyy-mm-dd
	char descrip[GOODS_DESCRIP_LEN + 1];//��Ʒ��������Ϣ,������100���ַ�
	GoodState goodsstate;//��ʾ��Ʒ״̬��ö������
};