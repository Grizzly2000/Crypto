#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

//Bob-side
//Bob get g and p known by everyone.
//Bob get A (g^x[p]) computed by Alice
//Bob choose randomly y to compute B (g^y[p])
//Bob compute the shared key (B^A[p])

#define SIZE_SECRET 1024

#define BUFFER 1024
#define IP "127.0.0.1"
#define PORT 8888

int CreateServer();
int DiffieHellmanBob();

int CreateServer()
{
	//Init Socket
    int socket_desc , client_sock , c;
    struct sockaddr_in server , client;
    
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Error : Could not create socket\n");
        return -1;
    }
    printf("Socket created\n");
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( PORT );
     
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        printf("Error : bind failed\n");
        return -1;
    }
    printf("Bind done\n");
    //Listen
    listen(socket_desc , 3);
     
    //Accept and incoming connection
    printf("Waiting for incoming connections... (launch dh_client.exe)\n");
    c = sizeof(struct sockaddr_in);


	//accept connection from an incoming client
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
    {
        printf("Error : accept failed\n");
        return -1;
    }
    printf("Connection accepted with Alice\n");
    
	return client_sock;
}

int DiffieHellmanBob(int client_sock)
{
	//GMP var init
	mpz_t y; mpz_init(y);
	mpz_t g; mpz_init(g);
	mpz_t p; mpz_init(p);
	mpz_t A; mpz_init(A);
	mpz_t B; mpz_init(B);
	mpz_t shared_key; mpz_init(shared_key);
	
	char client_message[BUFFER] = {0};
    int read_size = 0;
    
    //Gather informations send by Alice
    //g
    if( (read_size = recv(client_sock , client_message , BUFFER , 0)) < 0){puts("recv failed");return -1;}
    mpz_set_str(g,client_message,10);
    //p
    if( (read_size = recv(client_sock , client_message , BUFFER , 0)) < 0){puts("recv failed");return -1;}
    mpz_set_str(p,client_message,10);
    //A (g^x[p])
    if( (read_size = recv(client_sock , client_message , BUFFER , 0)) < 0){puts("recv failed");return -1;}
    mpz_set_str(A,client_message,10);
    
    printf("######################### Data from Alice #########################\n\n");
    printf("Known value by Alice and Bob (g and p)\n");
    gmp_printf("g : \n%Zd\n",g);
    gmp_printf("p : \n%Zd\n",p);
    gmp_printf("A (g^x[p]) computed by Alice: \n%Zd\n\n",A);
    
    
    printf("######################### Data generated by Bob #########################\n\n");
    //Bob select randomly y.
    srand(time(NULL));
	gmp_randstate_t r_state;
	gmp_randinit_default (r_state);
	gmp_randseed_ui(r_state, rand());
	mpz_urandomb(y,r_state, SIZE_SECRET);
	gmp_printf("y (secret) chosen by Bob : \n%Zd\n",y);
    
    //Compute B = g^y[p]
	mpz_powm(B, g, y, p);
	gmp_printf("Bob compute B (g^y[p]) = \n%Zd\n\n", B);
	

	//send value of B to Alice
	mpz_get_str(client_message,10,B);
    if( send(client_sock , client_message , sizeof(client_message) , 0) < 0){puts("send failed");return -1;}
    printf("Bob send value of B to Alice\n\n");
	
	printf("######################### Shared key #########################\n\n");

	//Compute shared key
	mpz_powm(shared_key,A,y,p);
	gmp_printf("Shared key (A^y[p]) : \n%Zd\n\n",shared_key);
	
    //Free
	gmp_randclear(r_state);
	mpz_clear(g);
	mpz_clear(y);
	mpz_clear(p);
	mpz_clear(A);
	mpz_clear(B);
	mpz_clear(shared_key);
	
	return 0;
}

int main()
{
	int client_sock = 0;
	//Create connection and wait the client
	if( (client_sock =CreateServer()) == -1)
	{
		printf("Server creation has failed\n");
		return -1;
	}
	
	//DiffieHellman Bob-side
	if(DiffieHellmanBob(client_sock) != 0)
	{
		printf("Diffie Hellman has failed\n");
		return -1;
	}
	
    return 0;
}
