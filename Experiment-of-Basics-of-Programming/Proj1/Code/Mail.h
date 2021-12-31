#pragma once

const int MAIL_TIME_LEN = 10;
const int CONTENT_LEN = 200;
const int NAME_LEN = 15;



class Mail {
public:
	Mail(const int _id, const int _sender_id, const int _reci_id, const char* _sender_name, const char* _reci_name, const char* _mail_time, const char* _content);
	Mail();


	int id;//�ʼ�id,ʵ����S��ͷ
	int sender_id;//������id
	int reci_id;//�ռ���id	
	char sender_name[NAME_LEN + 1];
	char reci_name[NAME_LEN + 1];
	char mail_time[MAIL_TIME_LEN + 1];
	char content[CONTENT_LEN + 1];
	bool isread;//�Ƿ��Ѷ�
};
