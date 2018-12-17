#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include <openssl/sha.h>

#define MODULUS_SIZE 4096
#define SHA1_SIZE 20

/* La taille maximale d'un bloc de message pour le chiffrer en RSA est de MODULUS_SIZE/8 octets
 * Cependant, avant d'être chiffré, le message en clair doit être encodé en PKCS#1 2.1
 * La taille maximale d'un message en clair, pour obtenir un message encodé de taille MODULUS_SIZE/8 octets, est de MODULUS_SIZE/8 -2*SHA1_SIZE -2 octets
 * Pour chiffrer le message, on divise donc le message en blocs de cette taille.
 * Pour le déchiffrer, on prend des blocs de taille MODULUS_SIZE/8 octets, car ce sont des blocs de cette taille qui sont produits par le chiffrement.
 */
#define BLOCK_SIZE_ENCRYPT ((MODULUS_SIZE / 8) - (2 * SHA1_SIZE) - 2)
#define BLOCK_SIZE_DECRYPT (MODULUS_SIZE / 8)

typedef struct {
	mpz_t n;
	mpz_t e;
} pub_key;

typedef struct {
	mpz_t p;
	mpz_t q;
	mpz_t d;
	mpz_t n;
} priv_key;

/*
 * gen_keys
 * Génération de clés RSA privée et publique de taille MODULUS_SIZE bits
 * RFC 3447 - Section 3
 * Input: puk - Pointeur vers la structure qui contiendra les valeurs de la clé publique (initialisées au préalable avec mpz_init) - struct pub_key *
 * Input: prk - Pointeur vers la structure qui contiendra les valeurs de la clé privée (initialisées au préalable avec mpz_init) - struct priv_key *
 */
void gen_keys(pub_key* puk, priv_key* prk)
{
	printf("----- GENERATING KEYS -----\n");

	//Initialisation de l'aleatoire
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, rand());

	mpz_t phi, tmp1, tmp2, tmp3, two, twopowmod;
	mpz_init(phi);
	mpz_init(tmp1);
	mpz_init(tmp2);
	mpz_init(tmp3);
	mpz_init(two);
	mpz_init(twopowmod);

	//On définit e à 17
	mpz_set_ui(puk->e, 17);

	//On calcule la valeur de 2^(Modulus-1), pour être sûrs que n fera la taille demandée
	mpz_set_ui(two, 2);
	mpz_pow_ui(twopowmod, two, MODULUS_SIZE-1);

	do {
		//Génération de deux nombres aléatoires
		mpz_urandomb(tmp1, state, MODULUS_SIZE/2);
		mpz_urandomb(tmp2, state, MODULUS_SIZE/2);

		//On fait en sorte que le produit de ces nombres fasse MODULUS bits, pour être sur que le Modulus soit assez grand
		mpz_mul(tmp3, tmp1, tmp2);
		if(mpz_cmp(twopowmod, tmp3) > 0)
		{
			//Pour que le test du while soit évalué a false
			mpz_set(tmp1, puk->e);
			continue;
		}

		//Calcul de deux nombres premiers à partir de ces nombres
		mpz_nextprime(prk->p, tmp1);
		mpz_nextprime(prk->q, tmp2);

		//Calcul du modulus
		mpz_mul(puk->n, prk->p, prk->q);

		//Calcul de phi
		mpz_sub_ui(tmp1, prk->p, 1);
		mpz_sub_ui(tmp2, prk->q, 1);
		mpz_mul(phi, tmp1, tmp2);

		//On vérifie que phi et e soient premiers entre eux
		mpz_gcd(tmp1, phi, puk->e);
	} while (!mpz_cmp(tmp1, puk->e));

	//On met n également dans la clé privée, pour raison de commodité
	mpz_set(prk->n, puk->n);

	//On calcule d en fonction de e et phi
	mpz_invert(prk->d, puk->e, phi);

	mpz_clear(phi);
	mpz_clear(tmp1);
	mpz_clear(tmp2);
	mpz_clear(tmp3);
	mpz_clear(two);
	mpz_clear(twopowmod);
}

void print_keys(pub_key puk, priv_key prk)
{
	printf("PUBLIC\n");
	gmp_printf("%Zd\n", puk.n);
	gmp_printf("%Zd\n", puk.e);
	printf("PRIVATE\n");
	gmp_printf("%Zd\n", prk.p);
	gmp_printf("%Zd\n", prk.q);
	gmp_printf("%Zd\n\n", prk.d);
}

void print_hex(const unsigned char * str, unsigned int len)
{
	int i;
	for(i = 0; i < len; i++)
		printf("%02x ", (unsigned int) *str++);
	printf("\n");
}

/*
 * Mask Generating Function
 * Generation d'un masque aléatoire d'une taille donnée à partir d'une graine donnée
 * RFC 3447 - Appendix B.2
 * Input: seed - Graine - char array
 * Input: mask_length - Longueur voulue - int
 * Output: Masque - char array de taille mask_length
 */
unsigned char * MGF(unsigned char * seed, unsigned int mask_length)
{
	unsigned int i, j;
	unsigned char * T;
	unsigned char * returned_array;
	unsigned char C[4];
	unsigned char tempT[SHA1_SIZE];
	unsigned char seed_counter[SHA1_SIZE + 4];

	// seed_counter est la concatenation de la graine (taille SHA1_SIZE octets) et du compteur de la boucle qui suit (taille 4 octets)
	for(i = 0; i < SHA1_SIZE; i++)
	{
		seed_counter[i] = seed[i];
	}

	// On génère SHA1_SIZE octets de masque par itération, donc on itère jusqu'a ce qu'on ait généré au moins mask_length octets
	for(i = 0; i <= (int)((float)(mask_length - 1) / (float)SHA1_SIZE); i++)
	{
		// On passe le compteur sour la forme d'un tableau de 4 octets
		C[0] = (i >> 24) & 0xFF;
		C[1] = (i >> 16) & 0xFF;
		C[2] = (i >> 8) & 0xFF;
		C[3] = i & 0xFF;

		// On concatène le compteur à la graine
		seed_counter[SHA1_SIZE] = C[0];
		seed_counter[SHA1_SIZE + 1] = C[1];
		seed_counter[SHA1_SIZE + 2] = C[2];
		seed_counter[SHA1_SIZE + 3] = C[3];

		// On calcule le hash SHA1 de ce tableau
		SHA1(seed_counter, sizeof(seed_counter), tempT);

		// On alloue le tableau à la première itération, et on le réalloue avec une plus grande taille aux prochaines itérations
		if(!i)
		{
			T = (unsigned char *)malloc(SHA1_SIZE * sizeof(unsigned char));
		}
		else
		{
			T = (unsigned char *)realloc(T, SHA1_SIZE * (i + 1)  * sizeof(unsigned char));
		}

		// On concatène les nouveaux octets générés avec les octets générés précedemment.
		for(j = 0; j < SHA1_SIZE; j++)
		{
			T[i * SHA1_SIZE + j] = tempT[j];
		}
	}

	// On ne retourne que mask_length octets
	returned_array = (unsigned char *)malloc(mask_length * sizeof(unsigned char));
	memcpy(returned_array, &T[0], mask_length * sizeof(unsigned char));

	free(T);

	return returned_array;
}

/*
 * pkcs_encode_message
 * Encode le message selon la norme PKCS#1 v2.1
 * RFC 3447 - Section 7.1.1.2
 * Input: message - Message à encoder - char array
 * Input: message_length - longueur en octets du message - int
 * Output: Message encodé de taille fixe (MODULUS_SIZE/8 octets)
 */
unsigned char * pkcs_encode_message(unsigned char * message, unsigned int message_length)
{
	unsigned char label[] = "";
	unsigned char label_hash[SHA1_SIZE];
	unsigned char seed[SHA1_SIZE];
	unsigned char * PS;
	unsigned char * DB;
	unsigned char * dbMask;
	unsigned char * maskedDB;
	unsigned char * seedMask;
	unsigned char * maskedSeed;
	unsigned char * encoded_message;
	unsigned int i, PS_size, DB_size;

	// Calcul du hash SHA1 du label (ici la chaine vide "\0")
	SHA1(label, sizeof(label), label_hash);

	// Initialisation de la Padding String (potentiellement de taille nulle) composée d'octets 0x00
	PS_size = (MODULUS_SIZE / 8) - message_length - (2 * SHA1_SIZE) - 2;
	PS = (unsigned char *)calloc(PS_size, sizeof(unsigned char));

	// Calcul de la taille du Data Block
	DB_size = (MODULUS_SIZE / 8) - SHA1_SIZE - 1;

	// Création du datablock comme: label_hash || padding_string || 0x01 || message
	DB = (unsigned char *)malloc(DB_size * sizeof(unsigned char));
	for(i = 0; i < SHA1_SIZE; i++)
	{
		DB[i] = label_hash[i];
	}
	for(i = 0; i < PS_size; i++)
	{
		DB[i + SHA1_SIZE] = PS[i];
	}
	DB[SHA1_SIZE + PS_size] = 0x01;
	for(i = 0; i < message_length; i++)
	{
		DB[i + SHA1_SIZE + PS_size + 1] = message[i];
	}
	free(PS);

	// Génération d'une graine aléatoire de taille SHA1_SIZE octets
	for(i = 0; i < SHA1_SIZE; i++)
	{
		seed[i] = rand() % 256;
	}

	// Génération d'un masque de taille DB_size à partir de la graine
	dbMask = MGF(seed, DB_size);

	// Masquage du Data Block
	maskedDB = (unsigned char *)malloc(DB_size * sizeof(unsigned char));
	for(i = 0; i < DB_size; i++)
	{
		maskedDB[i] = (DB[i] ^ dbMask[i]) & 0xFF;
	}
	free(DB);
	free(dbMask);	

	// Génération d'un masque de taille SHA1_SIZE octets à partir du Data Block masqué
	seedMask = MGF(maskedDB, SHA1_SIZE);

	// Masquage de la seed
	maskedSeed = (unsigned char *)malloc(SHA1_SIZE * sizeof(unsigned char));
	for(i = 0; i < SHA1_SIZE; i++)
	{
		maskedSeed[i] = (seed[i] ^ seedMask[i]) & 0xFF;
	}
	free(seedMask);

	// Création du message encodé comme: 0x00 || maskedSeed || maskedDB
	encoded_message = (unsigned char *)malloc((MODULUS_SIZE/8) * sizeof(unsigned char));
	encoded_message[0] = 0x00;
	for(i = 0; i < SHA1_SIZE; i++)
	{
		encoded_message[1 + i] = maskedSeed[i];
	}
	for(i = 0; i < DB_size; i++)
	{
		encoded_message[1 + i + SHA1_SIZE] = maskedDB[i];
	}

	free(maskedDB);
	free(maskedSeed);

	return encoded_message;
}

/* encrypt_message
 * Chiffrement d'un message d'une taille arbitraire selon l'algorithme RSA
 * Input: cipher_size - Pointeur vers une variable qui contiendra la taille totale en octet du message une fois chiffré - int *
 * Input: message - Tableau de chars contenant chaque octet du message à chiffrer - char array
 * Input: message_length - Taille du message à chiffrer - int
 * Input: puk - Clé publique contenant les primitives e et n utilisées pour chiffrer le message - struct pub_key
 * Output: Tableau contenant les octets du message chiffré - char array
 */
unsigned char * encrypt_message(unsigned int * cipher_size, unsigned char message[], unsigned int message_length, pub_key puk)
{
	printf("--- BEGINING ENCRYPTION ---\n");
	unsigned char * current_encoded_message;
	unsigned char * cipher;
	unsigned char * tmp_cipher;
	unsigned char buffer[BLOCK_SIZE_ENCRYPT];
	unsigned int current_offset, old_size, i, to_process, current_message_length, current_encoded_message_length, nb_zeroes;
	size_t nb_copied;
	mpz_t current_message, current_cipher;
	mpz_init(current_message);
	mpz_init(current_cipher);

	int tmp = 0;

	current_offset = 0;
	old_size = 0;
	*cipher_size = 0;

	// Un message encodé en PKCS#1 2.1 fera toujours une taille de MODULUS_SIZE/8 octets
	current_encoded_message_length = MODULUS_SIZE / 8;
	
	// On parcourt bloc par bloc (de taille BLOCK_SIZE_ENCRYPT) le message
	while(current_offset < message_length)
	{
		tmp++;
		// Sommes-nous à la fin du message?
		to_process = message_length - current_offset;
		current_message_length = (to_process > BLOCK_SIZE_ENCRYPT) ? BLOCK_SIZE_ENCRYPT : to_process;

		// On initialise un buffer de taille BLOCK_SIZE_ENCRYPT (ou du reste du message) contenant un bloc du message a chiffrer
		memcpy(&buffer, &message[current_offset], current_message_length);

		// On encode le message en PKCS#1 2.1
		current_encoded_message = pkcs_encode_message(buffer, current_message_length);

		// On importe dans une variable gmp le message encodé
		mpz_import(current_message, current_encoded_message_length, 1, sizeof(unsigned char), 0, 0, current_encoded_message);
		free(current_encoded_message);

		// Chiffrement du message encodé (RFC 3447 - Section 5.1.1)
		mpz_powm(current_cipher, current_message, puk.e, puk.n);

		// Export des données chiffrées dans un tableau d'unsigned char
		tmp_cipher = mpz_export(NULL, &nb_copied, 1, sizeof(unsigned char), 0, 0, current_cipher);

		// Il faut rajouter nous-mêmes les octets initiaux 0x00, car il ne sont pas forcément présents au début du tableau
		nb_zeroes = BLOCK_SIZE_DECRYPT - nb_copied;
		if(nb_zeroes > 0)
		{
			tmp_cipher = (unsigned char *)realloc(tmp_cipher, BLOCK_SIZE_DECRYPT * sizeof(unsigned char));
			for(i = BLOCK_SIZE_DECRYPT - 1; i >= nb_zeroes; i--)
			{
				tmp_cipher[i] = tmp_cipher[i - nb_zeroes];
			}
			for(i = 0; i < nb_zeroes; i++)
			{
				tmp_cipher[i] = 0x00;
			}
		}
		nb_copied = BLOCK_SIZE_DECRYPT;

		old_size = *cipher_size;
		*cipher_size += nb_copied;

		// Au début, on initialise le tableau a retourner, et on le réalloue au cours des prochaines itérations
		if(!current_offset)
		{
			cipher = (unsigned char *)malloc(*cipher_size * sizeof(char));
		}
		else
		{
			cipher = (unsigned char *)realloc(cipher, *cipher_size * sizeof(char));
		}

		// On concatène le bloc chiffré actuel avec le cryptogramme entier
		for(i = old_size; i < *cipher_size; i++)
		{
			cipher[i] = tmp_cipher[i - old_size];
		}

		current_offset += current_message_length;
		free(tmp_cipher);
	}

	mpz_clear(current_message);
	mpz_clear(current_cipher);
	printf("----- ENCRYPTION DONE -----\n");
	return cipher;
}

/*
 * pkcs_decode_message
 * Décode le message selon la norme PKCS#1 v2.1
 * RFC 3447 - Section 7.1.2.3
 * Input: encoded_message - Message encodé à décoded - char array
 * Input: encoded_message_length - taille en octets du message encodé - int
 * Input: nb_decoded - Pointeur vers une variable qui prendra la valeur du nombre d'octets de message décodés - int *
 * Output: Message décodé de taille variable
 */
unsigned char * pkcs_decode_message(unsigned char * encoded_message, unsigned int encoded_message_length, unsigned int * nb_decoded)
{
	unsigned char label[] = "";
	unsigned char label_hash[SHA1_SIZE];
	unsigned char * maskedDB;
	unsigned char * maskedSeed;
	unsigned char * seedMask;
	unsigned char * seed;
	unsigned char * dbMask;
	unsigned char * DB;
	unsigned char * message;
	unsigned int i, DB_size, message_offset;

	// Calcul du hash SHA1 du label (ici la chaine vide "\0")
	SHA1(label, sizeof(label), label_hash);

	// Calcul de la taille du Data Block
	DB_size = (MODULUS_SIZE / 8) - SHA1_SIZE - 1;
	
	// Si le premier octet du message encodé n'est pas 0x00, erreur
	if(encoded_message[0])
	{
		printf("Decryption error1\n");
		exit(-1);
	}

	// Récupération de maskedSeed et maskedDB, car encoded_message = 0x00 || maskedSeed || maskedDB
	maskedSeed = (unsigned char *)malloc(SHA1_SIZE * sizeof(unsigned char));
	for(i = 0; i < SHA1_SIZE; i++)
	{
		maskedSeed[i] = encoded_message[1 + i];
	}
	maskedDB = (unsigned char *)malloc(DB_size * sizeof(unsigned char));
	for(i = 0; i < DB_size; i++)
	{
		maskedDB[i] = encoded_message[1 + SHA1_SIZE + i];
	}

	// Récupération du masque de la graine grâce à maskedDB
	seedMask = MGF(maskedDB, SHA1_SIZE);

	// Récupération de la seed
	seed = (unsigned char *)malloc(SHA1_SIZE * sizeof(unsigned char));
	for(i = 0; i < SHA1_SIZE; i++)
	{
		seed[i] = (maskedSeed[i] ^ seedMask[i]) & 0xFF;
	}
	free(seedMask);
	free(maskedSeed);
	
	// Récupération du masque du Data Block grâce à la seed
	dbMask = MGF(seed, DB_size);
	free(seed);

	// Récupération du Data Block
	DB = (unsigned char *)malloc(DB_size * sizeof(unsigned char));
	for(i = 0; i < DB_size; i++)
	{
		DB[i] = (maskedDB[i] ^ dbMask[i]) & 0xFF;
	}
	free(dbMask);
	free(maskedDB);

	// DB = label_hash || padded_string (chaine de 0x00 de taille n, n possiblement nul) || 0x01 || message
	// Donc si l'octet à la position SHA1_SIZE est 0x01, le reste de DB est le message
	if(DB[SHA1_SIZE] == 0x01)
	{
		message_offset = SHA1_SIZE + 1;
	}
	// Sinon, si l'octet à la position SHA1_SIZE est 0x00, alors on parcous le tableau jusqu'a trouver un octet non nul, le message est après celui-ci
	else if(DB[SHA1_SIZE] == 0x00)
	{
		i = 0;
		while(!DB[SHA1_SIZE + i])
			i++;
		message_offset = SHA1_SIZE + i + 1;
	}
	// Sinon, erreur
	else
	{
		printf("Decryption error23\n");
		exit(-1);
	}
	// On calcule la taille du message décodé
	*nb_decoded = DB_size - message_offset;

	// On récupère le message décodé
	message = (unsigned char *)malloc(*nb_decoded * sizeof(unsigned char));
	for(i = 0; i < *nb_decoded; i++)
	{
		message[i] = DB[i + message_offset];
	}

	free(DB);
	return message;	
}

/* decrypt_message
 * Déchiffrement d'un message selon l'algorithme RSA
 * Input: clear_size - Pointeur vers une variable qui contiendra la taille totale en octet du message une fois déchiffré - int *
 * Input: cipher - Tableau de chars contenant chaque octet du message à déchiffrer - char array
 * Input: cipher_length - Taille du message à déchiffrer - int
 * Input: prk - Clé privée contenant les primitives d et n utilisées pour déchiffrer le message - struct priv_key
 * Output: Tableau contenant les octets du message déchiffré - char array
 */
unsigned char * decrypt_message(unsigned int * clear_size, unsigned char * cipher, unsigned int cipher_length, priv_key prk)
{
	printf("--- BEGINING DECRYPTION ---\n");
	
	unsigned char buffer[BLOCK_SIZE_DECRYPT];
	unsigned char * clear_message;
	unsigned char * tmp_clear;
	unsigned char * current_encoded_message;
	size_t nb_copied;
	unsigned int current_offset, old_size, i, to_process, current_cipher_length, nb_decoded, nb_zeroes;
	mpz_t current_cipher, current_clear;
	mpz_init(current_cipher);
	mpz_init(current_clear);

	current_offset = 0;
	old_size = 0;
	*clear_size = 0;
	// On parcours bloc par bloc (de taille BLOCK_SIZE_DECRYPT) le cryptogramme
	while(current_offset < cipher_length)
	{
		// Sommes-nous à la fin du cryptogramme?
		to_process = cipher_length - current_offset;
		current_cipher_length = (to_process > BLOCK_SIZE_DECRYPT) ? BLOCK_SIZE_DECRYPT : to_process;

		// On initialise un buffer de taille BLOCK_SIZE_DECRYPT (ou du reste du message) contenant un bloc du message a déchiffrer
		memcpy(&buffer, &cipher[current_offset], current_cipher_length);
	
		// On importe dans une variable gmp le cryptogramme
		mpz_import(current_cipher, current_cipher_length, 1, sizeof(unsigned char), 0, 0, buffer);

		// Déchiffrement du message (RFC 3447 - Section 5.1.2)
		mpz_powm(current_clear, current_cipher, prk.d, prk.n);

		// Export des données déchiffrées dans un tableau d'unsigned chars
		current_encoded_message = mpz_export(NULL, &nb_copied, 1, sizeof(unsigned char), 0, 0, current_clear);

		// Il faut rajouter nous-mêmes les octets initiaux 0x00, car il ne sont pas forcément présents au début du tableau
		nb_zeroes = BLOCK_SIZE_DECRYPT - nb_copied;
		current_encoded_message = (unsigned char *)realloc(current_encoded_message, BLOCK_SIZE_DECRYPT * sizeof(unsigned char));
		for(i = BLOCK_SIZE_DECRYPT; i > nb_zeroes; i--)
		{
			current_encoded_message[i - 1] = current_encoded_message[i - nb_zeroes - 1];
		}
		for(i = 0; i < nb_zeroes; i++)
		{
			current_encoded_message[i] = 0x00;
		}

		// Décodage du message encodé selon l'algorithme PKCS#1 2.1
		tmp_clear = pkcs_decode_message(current_encoded_message, nb_copied, &nb_decoded);
		free(current_encoded_message);

		old_size = *clear_size;
		*clear_size += nb_decoded;

		//Au début, on initialise le tableau a retourner, et on le réalloue au cours des prochaines itérations
		if(!current_offset)
		{
			clear_message = (unsigned char *)malloc(*clear_size * sizeof(char));
		}
		else
		{
			clear_message = (unsigned char *)realloc(clear_message, *clear_size * sizeof(char));
		}

		//On concatène le bloc déchiffré actuel avec le message entier
		for(i = old_size; i < *clear_size; i++)
		{
			clear_message[i] = tmp_clear[i - old_size];
		}

		current_offset += current_cipher_length;
		free(tmp_clear);
	}

	mpz_clear(current_cipher);
	mpz_clear(current_clear);
	printf("----- DECRYPTION DONE -----\n");
	return clear_message;
}


int main(int argc, char ** argv)
{
	unsigned char * file_content;
	unsigned char * cipher;
	unsigned char * clear_message;
	unsigned int cipher_size = 0, clear_size = 0, length = 0, i;
	unsigned char buffer[MODULUS_SIZE] = {0};
	pub_key puk;
	priv_key prk;

	FILE * fin = NULL;
	FILE * fout = NULL;
	FILE * fkey = NULL;
	
	srand(time(NULL));
	mpz_init(puk.n);
	mpz_init(puk.e);
	mpz_init(prk.p);
	mpz_init(prk.q);
	mpz_init(prk.d);
	mpz_init(prk.n);

	
	//vérification des arguments
	if(argc < 4)
	{
		printf("usage : ./rsa.exe ( g public_key private_key | e infile outfile public_key | d infile outfile private_key )\n");
		printf("\tg : utilisé pour générer la clé publique et la clé privée.\n");
		printf("\te : utilisé pour chiffrer infile en outfile avec la public_key.\n");
		printf("\td : utilisé pour déchiffrer infile en outfile avec la private_key.\n");
		
		return -1;
	}

	//Génération de la clé public et privée
	if(argv[1][0] == 'g')
	{
		gen_keys(&puk, &prk);
		printf("MODULUS_SIZE : %d\n",MODULUS_SIZE);
		
		//écriture de la clé publique
		fin = fopen(argv[2], "wb");
		mpz_get_str(buffer,10,puk.n);
		fprintf(fin, "%s\n", buffer);
		mpz_get_str(buffer,10,puk.e);
		fprintf(fin, "%s\n", buffer);
		printf("Génération de la clé publique : %s\n",argv[2]);
		
		//écriture de la clé privée
		fout = fopen(argv[3], "wb");
		mpz_get_str(buffer,10,prk.p);
		fprintf(fout, "%s\n", buffer);
		mpz_get_str(buffer,10,prk.q);
		fprintf(fout, "%s\n", buffer);
		mpz_get_str(buffer,10,prk.d);
		fprintf(fout, "%s\n", buffer);
		mpz_get_str(buffer,10,prk.n);
		fprintf(fout, "%s\n", buffer);
		printf("Génération de la clé privée : %s\n",argv[3]);
		return 0;
	}
	
	//Lecture du fichier infile
	fin = fopen(argv[2], "rb");
	if (fin != NULL)
    {
		fseek(fin, 0, SEEK_END);
		length = ftell(fin);
		fseek(fin, 0, SEEK_SET);
		file_content = malloc (length);

		if (file_content)
		{
			fread (file_content, 1, length, fin);
		}
		fclose(fin);
	}
	else
	{
		printf("Error : fichier infile (%s)\n", argv[2]);
		return -1;
	}

	
	//chiffrement de infile -> outfile avec la clé publique
	if(argv[1][0] == 'e')
	{
		//lecture de la clé publique
		fkey = fopen(argv[4], "rb");
		if(fkey == NULL)
		{
			printf("Error : clé publique (%s)\n", argv[4]);
			return -1;
		}
		fgets(buffer, sizeof(buffer), fkey);
		mpz_set_str(puk.n,buffer,10);
		fgets(buffer, sizeof(buffer), fkey);
		mpz_set_str(puk.e,buffer,10);
		
		//chiffrement RSA avec la clé publique
		cipher = encrypt_message(&cipher_size, file_content, length, puk);
		
		//ecriture dans le fichier outfile
		fout = fopen(argv[3], "wb");
		if (fout != NULL)
		{
		    for(i = 0; i < cipher_size; i++)
			{
				fputc(cipher[i], fout);
			}
			printf("Chiffrement terminé : %s\n", argv[3]);
		    fclose(fout);
		    free(cipher);
		}
		else
		{
			printf("Error : fichier outfile (%s)\n", argv[3]);
			return -1;
		}
	}

	//déchiffrement de infile -> outfile avec la clé privée
	if(argv[1][0] == 'd')
	{
		//lecture de la clé publique
		fkey = fopen(argv[4], "rb");
		if(fkey == NULL)
		{
			printf("Error : clé privé (%s)\n", argv[4]);
			return -1;
		}
		fgets(buffer, sizeof(buffer), fkey);
		mpz_set_str(prk.p,buffer,10);
		fgets(buffer, sizeof(buffer), fkey);
		mpz_set_str(prk.q,buffer,10);
		fgets(buffer, sizeof(buffer), fkey);
		mpz_set_str(prk.d,buffer,10);
		fgets(buffer, sizeof(buffer), fkey);
		mpz_set_str(prk.n,buffer,10);
		
		//déchiffrement RSA avec la clé publique
		
		
		clear_message = decrypt_message(&clear_size, file_content, length, prk);
		
		//ecriture dans le fichier outfile
		fout = fopen(argv[3], "wb");
		if (fout != NULL)
		{
		    for(i = 0; i < clear_size; i++)
			{
				fputc(clear_message[i], fout);
			}
			printf("Déchiffrement terminé : %s\n", argv[3]);
		    fclose(fout);
		    free(clear_message);
		}
		else
		{
			printf("Error : fichier outfile (%s)\n", argv[3]);
			return -1;
		}
	}

	mpz_clear(puk.n);
	mpz_clear(puk.e);
	mpz_clear(prk.n);
	mpz_clear(prk.p);
	mpz_clear(prk.q);
	mpz_clear(prk.d);

	return 0;
}
