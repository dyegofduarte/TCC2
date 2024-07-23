import sys
import re
import json
import vt
import requests
import time
import colorama

colorama.init()

# Chave de API do VirusTotal
API_KEY = open("api_key.txt", "r").read().strip()



# FUNÇÃO PARA BUSCA DAS STRINGS
def busca_strings(amostra, config, tamanho_min=4):
    # ABRE O ARQUIVO EM MODO BINÁRIO
    with open(amostra, 'rb') as f:
        conteudo = f.read().decode('ascii', 'ignore')  # DESCARTA BYTES QUE NÃO SÃO ASCII

        lista_strings = []  # LISTA QUE RECEBE STRINGS ENCONTRADAS

        # CRIA UM PADRÃO DE STRINGS ASCII COM MÍNIMO DE TAMANHO DEFINIDO ANTERIORMENTE COMO 4 
        ascii_regex = re.compile(r'[ -~]{' + str(tamanho_min) + r',}')

        # BUSCA POR CADA PADRÃO DE STRING
        for padrao_nome, padrao_regex in config.items():
            # SE O PADRÃO FOR all BUSCA TODAS AS STRINGS LEGÍVEIS
            if padrao_nome == 'all':
                string_encontrada = ascii_regex.findall(conteudo)
            else:
                # CASO CONTRÁRIO USA O PADRÃO ESPECIFICADO NO ARQUIVO config.json
                string_encontrada = re.findall(padrao_regex, conteudo)
            # ADICIONA A LISTA DE RESULTADOS OS VALORES ENCONTRADOS
            for match in string_encontrada:
                lista_strings.append(match)

            return lista_strings  # RETORNA A LISTA COM OS RESULTADOS

# FUNÇÃO PARA SELECIONA O PADRÃO DE STRINGS
def selec_padrao_string(padrao_selecionado, amostra):
    padroes_escolhidos = padrao_selecionado
    with open("config.json", "r") as f:
        todos_padroes = json.load(f)

    if 'all' in padroes_escolhidos:
        padrao = {'all': None}
    else:
        padrao = {k: todos_padroes[k] for k in padroes_escolhidos if k in todos_padroes}
    for s in busca_strings(amostra, padrao):
        print(s)

    return


#############################################
# FUNÇÃO PARA DETECÇÃO DE MALWARE
def detect(arquivo_amostra):
    resposta_upload = upload_amostra(arquivo_amostra)
    if resposta_upload:
        id_analise = resposta_upload['data']['id']
        print(f"Arquivo enviado com sucesso. ID da análise: {id_analise}")

        # Aguardar alguns segundos para a análise ser concluída (Tempo pode ser customizável)
        time.sleep(60)  # 60 segundos

        resultado_analise = get_resultado_analise(id_analise)
        if resultado_analise:
            print("Resultados da Análise:")
            for engine, result in resultado_analise['data']['attributes']['results'].items():
                print(f"Motor: {engine}")
                print(f"  Categoria: {result['category']}")
                print(f"  Resultado: {result['result']}")
                print(f"  Método: {result['method']}")
                print("")
    sys.exit(1)


# Função de upload do arquivo para o VirusTotal
def upload_amostra(arquivo_amostra):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': API_KEY,
    }
    files = {
        'file': (arquivo_amostra, open(arquivo_amostra, 'rb'))
    }

    response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Erro ao fazer upload do arquivo: {response.status_code}")
        return None

# FUNÇÃO PARA OBTER O RESULTADO DA ANÁLISE
def get_resultado_analise(id_analise):
    url = f'https://www.virustotal.com/api/v3/analyses/{id_analise}'
    headers = {
        'x-apikey': API_KEY,
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Erro ao obter resultados da análise: {response.status_code}")
        return None


#############################################
# FUNÇÃO PARA REPORT
def report(arquivo_amostra):
    resposta_upload = upload_amostra(arquivo_amostra)
    total_engines = 0
    total_detectados =0
    
    print("Gerando Report.....")
    
    if resposta_upload:
        id_analise = resposta_upload['data']['id']

        # Aguardar alguns segundos para a análise ser concluída (Tempo pode ser customizável)
        time.sleep(60)  # 60 segundos

        resultado_analise = get_resultado_analise(id_analise)
        if resultado_analise:
            for engine, result in resultado_analise['data']['attributes']['results'].items():
                total_engines = total_engines + 1
                if (result['result']) != None:
                    total_detectados = total_detectados + 1
    print(colorama.Fore.YELLOW + "\n >>> Resultado do report <<<\n" + colorama.Fore.RESET)
    print("Total de Motores Testados: ", total_engines)
    print("Total de Motores que detectaram: ", total_detectados)
    prob_malware = (total_detectados * 100) / total_engines # REGRA DE 3 PARA SABER A PORCENTAGEM QUE AS ENGINES DETECTADOS REPRESENTA DO TOTAL DE ENGINES USADAS
    print("Probabilidade de ser um Malware: " + colorama.Fore.RED + f"{prob_malware}" + colorama.Fore.RESET)

    print("\n\n ")

    print(colorama.Fore.BLUE + "Strings Relevantes" + colorama.Fore.RESET)
    print("\n")

    print(colorama.Fore.BLUE + "IPV4" + colorama.Fore.RESET)
    padroes_escolhidos = ['ipv4']
    selec_padrao_string(padroes_escolhidos, arquivo_amostra)
    print("\n")

    print(colorama.Fore.BLUE + "IPV6" + colorama.Fore.RESET)
    padroes_escolhidos = ['ipv6']
    selec_padrao_string(padroes_escolhidos, arquivo_amostra)
    print("\n")

    print(colorama.Fore.BLUE + "ENDEREÇOS MAC" + colorama.Fore.RESET)
    padroes_escolhidos = ['mac']
    selec_padrao_string(padroes_escolhidos, arquivo_amostra)
    print("\n")

    print(colorama.Fore.BLUE + "URLs" + colorama.Fore.RESET)
    padroes_escolhidos = ['url']
    selec_padrao_string(padroes_escolhidos, arquivo_amostra)
    print("\n")

    print(colorama.Fore.BLUE + "E-MAILs" + colorama.Fore.RESET)
    padroes_escolhidos = ['email']
    selec_padrao_string(padroes_escolhidos, arquivo_amostra)
    print("\n")

    print(colorama.Fore.BLUE + "DIRETÓRIOS" + colorama.Fore.RESET)
    padroes_escolhidos = ['dir']
    selec_padrao_string(padroes_escolhidos, arquivo_amostra)
    print("\n")

    sys.exit(1)


#############################################
# FUNÇÃO PARA MOSTRAR MANUAL
def manual():
    print("Formas de uso: python MyFDM.py <Amostra> <parâmetro>")
    print("Possíveis Parâmetros para obter Strings: ipv4 | ipv6 | mac | url | email | dir")
    print("Use 'all' como parametro para obter todos os tipos de Strings.")
    print("Use 'detect' para realizar a Detecção de Malware nos motores usados pelo VirusTotal")
    print("Use 'report' para um Report mais detalhado")
	print("Caso a saída seja muito grande, use '| less' no final do comando para uma melhor visualização")
    sys.exit(1)


#############################################

# FUNÇÃO MAIN
if __name__ == "__main__":
    if len(sys.argv) < 3:
        manual()
    
    amostra = sys.argv[1]

    if sys.argv[2] == 'detect':
        detect(amostra)

    elif sys.argv[2] == 'report':
        report(amostra)
    
    elif sys.argv[2] == 'ipv4' or 'ipv6' or 'mac' or 'url' or 'email' or 'dir':
        padroes_escolhidos = sys.argv[2].split(',')
        selec_padrao_string(padroes_escolhidos, amostra)

    else:
        manual()

