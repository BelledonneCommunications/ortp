/*
 * Copyright (c) 2010-2019 Belledonne Communications SARL.
 *
 * This file is part of oRTP.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include <ortp/ortp.h>

int main(int argc, char *argv[]){
	char value[256]={0};
	if (argc<3){
		fprintf(stderr,"%s <fmtp-line> <param-to-extract>\n", argv[0]);
		return -1;
	}
	if (fmtp_get_value(argv[1],argv[2],value,sizeof(value))){
		printf("%s\n", value);
	}else{
		fprintf(stderr,"No such parameter\n");
	}
	return 0;
}
