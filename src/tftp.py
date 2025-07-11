''' Diogo Pereira & June Pinto 11/07/25 '''

import string  # Para verificar caracteres ASCII
import struct  # Para criar os pacotes TFTP

MAX_DATA_LEN = 512  # Tamanho máximo do pacote de dados
DEFAULT_MODE = "octet"  # Modo de transferência (binário)

''' Tipos de pacotes TFTP possíveis '''
RRQ = 1  # Read Request
WRQ = 2  # Write Request
DAT = 3  # Data Packet
ACK = 4  # Acknowledgment Packet
ERR = 5  # Error Packet

""" Tipos de erros TFTP """
ERR_NOT_DEFINED = 0  # Erro indefinido
ERR_FILE_NOT_FOUND = 1  # Ficheiro não encontrado
ERR_ACCESS_VIOLATION = 2  # Acesso negado
ERR_DISK_FULL = 3  # Disco cheio
ERR_ILLEGAL_OPERATION = 4  # Operação ilegal
ERR_UNKNOWN_TID = 5  # ID de transação desconhecido
ERR_FILE_EXISTS = 6  # Ficheiro já existe
ERR_NO_SUCH_USER = 7  # Utilizador não identificado

''' Mensagens de erro correspondentes '''
ERROR_MESSAGES = {
    ERR_NOT_DEFINED: "Indefinido, verifique a mensagem de erro",
    ERR_FILE_NOT_FOUND: "Ficheiro não encontrado",
    ERR_ACCESS_VIOLATION: "Acesso negado",
    ERR_DISK_FULL: "Disco cheio",
    ERR_ILLEGAL_OPERATION: "Operação Ilegal TFTP",
    ERR_UNKNOWN_TID: "ID de Transação Desconhecido",
    ERR_FILE_EXISTS: "O ficheiro já existe",
    ERR_NO_SUCH_USER: "Utilizador não identificado"
}

''' Cria pacote RRQ (Read Request) '''
def pack_rrq(filename: str, mode=DEFAULT_MODE) -> bytes:
    return _pack_rq(RRQ, filename, mode)

''' Cria pacote WRQ (Write Request) '''
def pack_wrq(filename: str, mode=DEFAULT_MODE) -> bytes:
    return _pack_rq(WRQ, filename, mode)

''' Função auxiliar para empacotar um RRQ ou WRQ '''
def _pack_rq(opcode: int, filename: str, mode=DEFAULT_MODE) -> bytes:
    if not is_ascii_printable(filename):
        raise TFTPValueError("O nome do ficheiro deve conter apenas caracteres ASCII imprimíveis.")
    filename_bytes = filename.encode('utf-8') + b'\x00'
    mode_bytes = mode.encode('utf-8') + b'\x00'
    return struct.pack(f'!H{len(filename_bytes)}s{len(mode_bytes)}s', opcode, filename_bytes, mode_bytes)

''' Extrai o opcode do pacote '''
def unpack_opcode(packet: bytes) -> int:
    opcode, = struct.unpack('!H', packet[:2])
    if opcode not in (RRQ, WRQ, DAT, ACK, ERR):
        raise TFTPValueError(f"Código de operação inválido: {opcode}")
    return opcode

''' Cria pacote DAT (Data) '''
def pack_dat(block_number: int, data: bytes) -> bytes:
    if len(data) > MAX_DATA_LEN:
        raise TFTPValueError(f"Dados excedem {MAX_DATA_LEN} bytes.")
    return struct.pack(f'!HH{len(data)}s', DAT, block_number, data)

''' Extrai bloco e dados do pacote DAT '''
def unpack_dat(packet: bytes) -> tuple[int, bytes]:
    opcode, block = struct.unpack('!HH', packet[:4])
    if opcode != DAT:
        raise TFTPValueError(f"Opcode inválido no DAT: {opcode}")
    return block, packet[4:]

''' Cria pacote ACK (Acknowledgment) '''
def pack_ack(block_number: int) -> bytes:
    return struct.pack('!HH', ACK, block_number)

''' Extrai bloco do pacote ACK '''
def unpack_ack(packet: bytes) -> int:
    opcode, block = struct.unpack('!HH', packet[:4])
    if opcode != ACK:
        raise TFTPValueError(f"Opcode inválido no ACK: {opcode}")
    return block
    
''' Cria pacote ERR (Error) '''
def pack_err(error_num: int, error_msg: str) -> bytes:
    if not is_ascii_printable(error_msg):
        raise TFTPValueError(f"Mensagem erro inválida: {error_msg}")
    msg_bytes = error_msg.encode('utf-8') + b'\x00'
    return struct.pack(f'!HH{len(msg_bytes)}s', ERR, error_num, msg_bytes)

''' Extrai código e mensagem do pacote ERR '''
def unpack_err(packet: bytes) -> tuple[int, str]:
    opcode, error_num = struct.unpack('!HH', packet[:4])
    if opcode != ERR:
        raise TFTPValueError(f"Opcode inválido no ERR: {opcode}")
    msg = packet[4:-1].decode('utf-8')
    return error_num, msg

''' Verifica se uma string contém apenas caracteres ASCII exibíveis '''
def is_ascii_printable(txt: str) -> bool:
    return set(txt).issubset(string.printable)

''' Exceção personalizada para erros TFTP '''
class TFTPValueError(ValueError):
    pass
