#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

//Alice-side
//Alice chose p and g. those values are known by everyone.
//Alice chose randomly x.
//Alice Compute A (g^x[p]) and send the result to Bob
//Bob send B (g^y[p]) and Alice compute the shared key (B^x[p]).

#define SIZE_KEY 1024

#define BUFFER 1024
#define IP "127.0.0.1"
#define PORT 8888

int ConnectToServer()
{
	//Init Socket
    int sock;
    struct sockaddr_in server;

    int state_give = 0;
    
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Error : Could not create socket\n");
        return -1;
    }
    printf("Socket created\n");
     
    server.sin_addr.s_addr = inet_addr(IP);
    server.sin_family = AF_INET;
    server.sin_port = htons( PORT );
 
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        printf("Error : Connection has failed\n");
        return -1;
    }
    printf("Connected to Bob\n");
    
    return sock;
}

int DiffieHellmanAlice(int sock)
{
	//GMP var init
	mpz_t x; mpz_init(x);
	mpz_t g; mpz_init(g);
	mpz_t p; mpz_init(p);
	mpz_t A; mpz_init(A);
	mpz_t B; mpz_init(B);
	mpz_t shared_key; mpz_init(shared_key);
	srand(time(NULL));
    
    char message[BUFFER];
    
	//Random parameters
	gmp_randstate_t r_state;
	gmp_randinit_default (r_state);
	gmp_randseed_ui(r_state, rand());

	//Generate g and p
	mpz_urandomb(g,r_state,SIZE_KEY);
	mpz_urandomb(p,r_state,SIZE_KEY);

	//... make them prime
	mpz_nextprime(g,g);
	mpz_nextprime(p,p);


	//Check if they are prime
	if(!mpz_probab_prime_p(g,37) || !mpz_probab_prime_p(p,37))
	{
		printf("Erreur de la generation des nombres premiers!\n");
		gmp_randclear(r_state);
		mpz_clear(g);
		mpz_clear(p);
		return -1;
	}

	//Alice select randomly x.
	mpz_urandomb(x,r_state, SIZE_KEY);

	//Compute A = g^x[p]
	mpz_powm(A, g, x, p);

    printf("######################### Data generated by Alice #########################\n\n");
    printf("Known value by Alice and Bob (g and p)\n");
    gmp_printf("g : \n%Zd\n",g);
    gmp_printf("p : \n%Zd\n",p);
    gmp_printf("x (secret) chosen by Alice : \n%Zd\n",x);
    gmp_printf("Alice compute A (g^x[p]) : \n%Zd\n\n",A);
    
    printf("Alice send A to Bob\n\n");
    
    //Alice send to Bob :
    //g 
    mpz_get_str(message,10,g);
    if( send(sock , message , sizeof(message) , 0) < 0){puts("send failed");return -1;}
    //p 
    mpz_get_str(message,10,p);
    if( send(sock , message , sizeof(message) , 0) < 0){puts("send failed");return -1;}
    //A
	mpz_get_str(message,10,A);
    if( send(sock , message , sizeof(message) , 0) < 0){puts("send failed");return -1;}

	
	printf("######################### Data from Bob #########################\n\n");
	//We receive B(g^y[p]) from Bob
	if(recv(sock , message , BUFFER , 0) < 0){puts("recv failed");return -1;}
	mpz_set_str(B,message,10);
    gmp_printf("B (g^y[p]) computed by Bob: \n%Zd\n\n",B);
    
    
    printf("######################### Shared key #########################\n\n");
    //Compute shared key
    mpz_powm(shared_key,B,x,p);
	gmp_printf("Shared key (B^x[p]) : \n%Zd\n\n",shared_key);
    
    //Free
	gmp_randclear(r_state);
	mpz_clear(g);
	mpz_clear(x);
	mpz_clear(p);
	mpz_clear(A);
	mpz_clear(B);
	mpz_clear(shared_key);
    close(sock);
	return 0;
}

int main()
{
	int sock = 0;
	
	//Create connection and wait the client
	if((sock = ConnectToServer()) == -1)
	{
		printf("Connection with server has failed\n");
		return -1;
	}
	
	//DiffieHellman Alice-side
	if(DiffieHellmanAlice(sock) != 0)
	{
		printf("Diffie Hellman has failed\n");
		return -1;
	}
	
    return 0;
}