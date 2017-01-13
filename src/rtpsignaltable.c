/*
 * The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) implementation with additional features.
 * Copyright (C) 2017 Belledonne Communications SARL
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */



#include <ortp/rtpsession.h>
#include "utils.h"


void rtp_signal_table_init(RtpSignalTable *table,RtpSession *session, const char *signal_name)
{
	memset(table,0,sizeof(RtpSignalTable));
	table->session=session;
	table->signal_name=signal_name;
	session->signal_tables=o_list_append(session->signal_tables,(void*)table);
}

int rtp_signal_table_add(RtpSignalTable *table,RtpCallback cb, void *user_data)
{
	int i;

	for (i=0;i<RTP_CALLBACK_TABLE_MAX_ENTRIES;i++){
		if (table->callback[i]==NULL){
			table->callback[i]=cb;
			table->user_data[i]=user_data;
			table->count++;
			return 0;
		}
	}
	return -1;
}


void rtp_signal_table_emit(RtpSignalTable *table)
{
	int i,c;

	for (i=0,c=0;c<table->count;i++){
		if (table->callback[i]!=NULL){
			c++;	/*I like it*/
			table->callback[i](table->session,table->user_data[i],0,0);
		}
	}
}

void rtp_signal_table_emit2(RtpSignalTable *table, void *arg)
{
	int i,c;

	for (i=0,c=0;c<table->count;i++){
		if (table->callback[i]!=NULL){
			c++;	/*I like it*/
			table->callback[i](table->session,arg,table->user_data[i],0);
		}
	}
}

void rtp_signal_table_emit3(RtpSignalTable *table, void *arg1, void *arg2)
{
	int i,c;

	for (i=0,c=0;c<table->count;i++){
		if (table->callback[i]!=NULL){
			c++;	/*I like it*/
			table->callback[i](table->session,arg1,arg2,table->user_data[i]);
		}
	}
}

int rtp_signal_table_remove_by_callback(RtpSignalTable *table,RtpCallback cb)
{
	int i;

	for (i=0;i<RTP_CALLBACK_TABLE_MAX_ENTRIES;i++){
		if (table->callback[i]==cb){
			table->callback[i]=NULL;
			table->user_data[i]=0;
			table->count--;
			return 0;
		}
	}
	return -1;
}
