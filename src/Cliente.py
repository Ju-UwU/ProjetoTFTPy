#!/usr/bin/env python3

'''Diogo Pereira & June Pinto
11/07/25'''

import socket
import sys
from tftp import *

'''Constantes'''
'''Porta do servidor TFTP'''
SERVER_PORT = 6969
'''Tamanho do pacote recebidos em bytes, vi que recomendam 1024 bytes'''
BUFFER_SIZE = 1024
'''Tempo máximo de espera (em segundos)'''
TIMEOUT = 60

def GET_Arquivo(ip, nome_arquivo):
    '''Função para baixar arquivo (GET)'''
    print("Fazendo download do servidor")

    '''Cria socket UDP'''
    soquete = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soquete.settimeout(TIMEOUT)  # Define timeout

    '''Envia pedido de leitura (RRQ)'''
    pacote_ReadRequest = pack_rrq(nome_arquivo)
    soquete.sendto(pacote_ReadRequest, (ip, SERVER_PORT))
    print("Pedido de leitura enviado")

    '''Abre arquivo para escrever os dados em binário'''
    arquivo = open(nome_arquivo, 'wb')
    '''Para começar a escrever dados, têm de começar no bloco 1'''
    numero_bloco = 1

    while True:
        '''Recebe pacote do servidor'''
        dados, endereco = soquete.recvfrom(BUFFER_SIZE)
        codigo = unpack_opcode(dados)

        '''Se for pacote de dados (DAT)'''
        if codigo == DAT:
            bloco, conteudo = unpack_dat(dados)
            if bloco == numero_bloco:           #Verifica se o número do bloco é o esperado.
                arquivo.write(conteudo)         #Escreve no arquivo
                pacote_ACK = pack_ack(bloco)    #TFTP exige que o cliente envie um ACK para cada bloco DAT recebido.
                soquete.sendto(pacote_ACK, endereco)    #Envia o pacote ACK ao servidor.
                if len(conteudo) < MAX_DATA_LEN:
                    print("Último bloco recebido, terminando...")
                    break                       #Encerra o loop, pois a transferência está completa
                numero_bloco = numero_bloco + 1 #Incrementa o número do bloco cada loop
            else:
                print("Não faz sentido o bloco, devia começar no 1")
                break

        '''Se for erro (ERR)'''
        if codigo == ERR:
            print("Erro do servidor")
            break

    '''Fecha tudo'''
    arquivo.close()
    soquete.close()
    print("Download terminado (ou deu erro).")

def PUTT_arquivo(ip, nome_arquivo):
    '''Função para enviar arquivo (PUT)'''
    print(f"Vou tentar enviar {nome_arquivo} para o servidor {ip}:{SERVER_PORT}")

    '''Cria socket UDP'''
    soquete = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soquete.settimeout(TIMEOUT)

    '''Envia pedido de escrita (WRQ)'''
    pacote_WriteRequest = pack_wrq(nome_arquivo)
    soquete.sendto(pacote_WriteRequest, (ip, SERVER_PORT))
    print("Enviei o pedido de escrita")

    '''Recebe resposta do servidor'''
    dados, endereco = soquete.recvfrom(BUFFER_SIZE)
    codigo = unpack_opcode(dados)

    if codigo != ACK:       #Se não for o código 4 de ACK. fecha tudo
        print("Resposta estranha ao WRQ")
        soquete.close()
        return

    bloco_ack = unpack_ack(dados)
    if bloco_ack != 0:      #Se os dados do ACK não começar no bloco 0, fecha tudo
        print("ACK errado, esperava 0")
        soquete.close()
        return

    print("ACK recebido, começando a enviar blocos!")

    '''Abre arquivo para leitura'''
    arquivo = open(nome_arquivo, 'rb')
    numero_bloco = 1

    while True:
        '''Lê até 512 bytes do arquivo'''
        conteudo = arquivo.read(MAX_DATA_LEN)
        pacote_dat = pack_dat(numero_bloco, conteudo)   #Cria um pacote para enviar ao servidor
        soquete.sendto(pacote_dat, endereco)            #Envia od dados para o servidor (endereço)

        '''Recebe ACK do servidor'''
        dados, endereco = soquete.recvfrom(BUFFER_SIZE)
        codigo = unpack_opcode(dados)

        if codigo == ACK:
            bloco_ack = unpack_ack(dados)
            if bloco_ack == numero_bloco:
                if len(conteudo) < MAX_DATA_LEN:
                    print("Último bloco enviado, terminando...")
                    break
                numero_bloco = numero_bloco + 1 #Incrementa o número do bloco cada loop

        elif codigo == ERR:
            print("Erro do servidor")
            break

    '''Fecha tudo'''
    arquivo.close()
    soquete.close()
    print("Upload terminado (ou deu erro).")

def Cliente_Interactivo():

    print("Bem-vindo ao cliente TFTP")
    print("Comandos: get <ip> <arquivo>, put <ip> <arquivo>, quit")

    while True:
        comando = input("tftp> ")

        if not comando:
            print("Digite um comando qualquer")
            continue
        '''Separa o comando com espaços(ex.: "get 192.168.1.1 arquivo.txt") para o programa analisar'''
        partes = comando.split() 
        if partes[0] == "get":
            ip = partes[1]
            arquivo = partes[2]
            GET_Arquivo(ip, arquivo)
        if partes[0] == "put":
            ip = partes[1]
            arquivo = partes[2]
            PUTT_arquivo(ip, arquivo)
        if partes[0] == "help":
            print("Comandos: get <ip> <arquivo>, put <ip> <arquivo>, quit")
        if partes[0] == "quit":
            print("Tchau amigo!")
            break

def Cliente_Nao_Interativo():
    '''Fazemos uma lista para ler os inputs'''
    comando, ip, arquivo = sys.argv[1], sys.argv[2], sys.argv[3]        
    if comando == "get":
        GET_Arquivo(ip, arquivo)
    elif comando == "put":
        PUTT_arquivo(ip, arquivo)
    else:
        print("Comando inválido: use get ou put, seguido com ip e o nome do arquivo")
        return


if __name__ == "__main__":
    """Se o script for chamado com 4 argumentos (como scrip + put/get + IP + nome do arquivo), ele entra no modo não interativo"""
    if len(sys.argv) == 4:
        Cliente_Nao_Interativo()
    else:                    #Caso contrário, entra no modo interativo
        Cliente_Interactivo()
