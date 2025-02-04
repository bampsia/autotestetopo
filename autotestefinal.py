from functools import partial
import time
import os
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from scapy.all import rdpcap
from scapy.layers.inet import TCP
import threading
import statistics
import json
import requests

onos_host = "http://localhost:8181/onos/v1"
auth = ("onos", "rocks")
headers = {"Content-Type": "application/json"}
apps_to_activate = [
    "org.onosproject.openflow",
    "org.onosproject.proxyarp",
    "org.onosproject.fwd"
]

def activate_app(app_name):
    url = f"{onos_host}/applications/{app_name}/active"
    response = requests.post(url, auth=auth)
    if response.status_code == 200:
        print(f"Aplicativo {app_name} ativado com sucesso.")
    else:
        print(f"Falha ao ativar {app_name}. Status: {response.status_code}, Resposta: {response.text}")

def deactivate_app(app_name):
    url = f"{onos_host}/applications/{app_name}/active"
    response = requests.delete(url, auth=auth)
    if response.status_code == 204:
        print(f"Aplicativo {app_name} desativado com sucesso.")
    else:
        print(f"Falha ao desativar {app_name}. Status: {response.status_code}, Resposta: {response.text}")


class GeneratedTopo(Topo):
	
	def __init__(self, **opts):
		
		Topo.__init__(self, **opts)

		# Adicionando Switches:
		
		Maceio = self.addSwitch('s1')
		CampinaGrande = self.addSwitch('s2')
		JoaoPessoa = self.addSwitch('s3')
		Brasilia = self.addSwitch('s4')
		BeloHorizonte = self.addSwitch('s5')
		Aracaju = self.addSwitch('s6')
		Salvador = self.addSwitch('s7')
		Vitoria = self.addSwitch('s8')
		RiodeJaneiro = self.addSwitch('s9')
		Manaus = self.addSwitch('s10')
		Goiania = self.addSwitch('s11')
		Cuiaba = self.addSwitch('s12')
		Curitiba = self.addSwitch('s13')
		PortoAlegre = self.addSwitch('s14')
		Florianopolis = self.addSwitch('s15')
		SaoPaulo = self.addSwitch('s16')
		PortoVelho = self.addSwitch('s17')
		RioBranco = self.addSwitch('s18')
		Palmas = self.addSwitch('s19')
		CampoGrande = self.addSwitch('s20')
		Teresina = self.addSwitch('s21')
		Natal = self.addSwitch('s22')
		RedCLARA = self.addSwitch('s23')
		InetnetComercial = self.addSwitch('s24')
		AmericasLight = self.addSwitch('s25')
		BoaVista = self.addSwitch('s26')
		Macapa = self.addSwitch('s27')
		Belem = self.addSwitch('s28')
		SaoLuis = self.addSwitch('s29')
		Fortaleza = self.addSwitch('s30')
		Recife = self.addSwitch('s31')

		# Adicionando Hosts:
		
		Maceio_host = self.addHost('h1')
		CampinaGrande_host = self.addHost('h2')
		JoaoPessoa_host = self.addHost('h3')
		Brasilia_host = self.addHost('h4')
		BeloHorizonte_host = self.addHost('h5')
		Aracaju_host = self.addHost('h6')
		Salvador_host = self.addHost('h7')
		Vitoria_host = self.addHost('h8')
		RiodeJaneiro_host = self.addHost('h9')
		Manaus_host = self.addHost('h10')
		Goiania_host = self.addHost('h11')
		Cuiaba_host = self.addHost('h12')
		Curitiba_host = self.addHost('h13')
		PortoAlegre_host = self.addHost('h14')
		Florianopolis_host = self.addHost('h15')
		SaoPaulo_host = self.addHost('h16')
		PortoVelho_host = self.addHost('h17')
		RioBranco_host = self.addHost('h18')
		Palmas_host = self.addHost('h19')
		CampoGrande_host = self.addHost('h20')
		Teresina_host = self.addHost('h21')
		Natal_host = self.addHost('h22')
		RedCLARA_host = self.addHost('h23')
		InetnetComercial_host = self.addHost('h24')
		AmericasLight_host = self.addHost('h25')
		BoaVista_host = self.addHost('h26')
		Macapa_host = self.addHost('h27')
		Belem_host = self.addHost('h28')
		SaoLuis_host = self.addHost('h29')
		Fortaleza_host = self.addHost('h30')
		Recife_host = self.addHost('h31')

		# Atribuindo Hosts a Switches:
		
		self.addLink(Recife, Recife_host)
		self.addLink(Maceio, Maceio_host)
		self.addLink(CampinaGrande, CampinaGrande_host)
		self.addLink(JoaoPessoa, JoaoPessoa_host)
		self.addLink(Brasilia, Brasilia_host)
		self.addLink(BeloHorizonte, BeloHorizonte_host)
		self.addLink(Aracaju, Aracaju_host)
		self.addLink(Salvador, Salvador_host)
		self.addLink(Vitoria, Vitoria_host)
		self.addLink(RiodeJaneiro, RiodeJaneiro_host)
		self.addLink(Manaus, Manaus_host)
		self.addLink(Goiania, Goiania_host)
		self.addLink(Cuiaba, Cuiaba_host)
		self.addLink(Curitiba, Curitiba_host)
		self.addLink(PortoAlegre, PortoAlegre_host)
		self.addLink(Florianopolis, Florianopolis_host)
		self.addLink(SaoPaulo, SaoPaulo_host)
		self.addLink(PortoVelho, PortoVelho_host)
		self.addLink(RioBranco, RioBranco_host)
		self.addLink(Palmas, Palmas_host)
		self.addLink(CampoGrande, CampoGrande_host)
		self.addLink(Teresina, Teresina_host)
		self.addLink(Natal, Natal_host)
		self.addLink(RedCLARA, RedCLARA_host)
		self.addLink(InetnetComercial, InetnetComercial_host)
		self.addLink(AmericasLight, AmericasLight_host)
		self.addLink(BoaVista, BoaVista_host)
		self.addLink(Macapa, Macapa_host)
		self.addLink(Belem, Belem_host)
		self.addLink(SaoLuis, SaoLuis_host)
		self.addLink(Fortaleza, Fortaleza_host)

		# Interligando Switches:
		
		self.addLink(Recife, CampinaGrande, bw=10, delay='0.728083306294ms')
		self.addLink(Recife, Teresina, bw=10, delay='4.75104651797ms')
		self.addLink(Maceio, Aracaju, bw=10, delay='1.02333132284ms')
		self.addLink(CampinaGrande, JoaoPessoa, bw=10, delay='0.574494128178ms')
		self.addLink(JoaoPessoa, Natal, bw=10, delay='0.77083515853ms')
		self.addLink(Brasilia, RiodeJaneiro, bw=10, delay='4.74645186569ms')
		self.addLink(Brasilia, BoaVista, bw=10, delay='12.6958735236ms')
		self.addLink(Brasilia, Macapa, bw=10, delay='9.10834160958ms')
		self.addLink(Brasilia, Manaus, bw=10, delay='9.82710271126ms')
		self.addLink(Brasilia, BeloHorizonte, bw=10, delay='3.1754047454ms')
		self.addLink(BeloHorizonte, SaoPaulo, bw=10, delay='2.49094748402ms')
		self.addLink(BeloHorizonte, Fortaleza, bw=10, delay='9.62662971295ms')
		self.addLink(BeloHorizonte, Salvador, bw=10, delay='4.90496312307ms')
		self.addLink(Aracaju, Salvador, bw=10, delay='1.40995388916ms')
		self.addLink(Salvador, Vitoria, bw=10, delay='4.26832509118ms')
		self.addLink(Vitoria, RiodeJaneiro, bw=10, delay='2.09838358952ms')
		self.addLink(RiodeJaneiro, SaoPaulo, bw=10, delay='1.81724986555ms')
		self.addLink(Goiania, Palmas, bw=10, delay='3.68648815185ms')
		self.addLink(Goiania, Cuiaba, bw=10, delay='3.76411437759ms')
		self.addLink(Cuiaba, PortoVelho, bw=10, delay='5.78650124499ms')
		self.addLink(Cuiaba, CampoGrande, bw=10, delay='2.84736240574ms')
		self.addLink(Curitiba, SaoPaulo, bw=10, delay='1.72261996317ms')
		self.addLink(Curitiba, CampoGrande, bw=10, delay='3.9680813909ms')
		self.addLink(Curitiba, PortoAlegre, bw=10, delay='2.78014060979ms')
		self.addLink(PortoAlegre, Florianopolis, bw=10, delay='1.9122108808ms')
		self.addLink(Florianopolis, SaoPaulo, bw=10, delay='2.48706488184ms')
		self.addLink(SaoPaulo, RedCLARA, bw=10, delay='11.8009174487ms')
		self.addLink(SaoPaulo, InetnetComercial, bw=10, delay='11.8009174487ms')
		self.addLink(SaoPaulo, AmericasLight, bw=10, delay='11.8009174487ms')
		self.addLink(PortoVelho, RioBranco, bw=10, delay='2.28302913616ms')
		self.addLink(Teresina, Belem, bw=10, delay='3.8159263049ms')
		self.addLink(Natal, Fortaleza, bw=10, delay='2.21408885905ms')
		self.addLink(Belem, SaoLuis, bw=10, delay='2.44914325405ms')
		self.addLink(SaoLuis, Fortaleza, bw=10, delay='3.31832252273ms')

def replay_capture(net, mbps, arquivo):
	
	h1 = 'h5'
	h2 = 'h17'
	#links = [('s16','s13')]
	links = [('s16','s13'),('s5','s16'),('s4','s9')]
	traffic_in = 'trafegoIn.pcap'
	traffic_out = 'trafegoOut.pcap'
	
	intent_data = {
	"type": "HostToHostIntent",
	"appId": "org.onosproject.cli",
	"one": "00:00:00:00:00:05/None",
	"two": "00:00:00:00:00:11/None"
	}
	
	response = requests.post(f"{onos_host}/intents", auth=auth, headers=headers, data=json.dumps(intent_data))
	
	if response.status_code == 201:
		intent_id = response.json().get("id")
		intent_id_hex = hex(int(intent_id))
		print(f"Intent instalado com ID: {intent_id}")
	else:
		print(f"Erro ao instalar o Intent: {response.status_code} - {response.text}")
				
	h1_pid = os.popen(f"pgrep -f 'mininet:{h1}' | head -n1").read().strip()
	h2_pid = os.popen(f"pgrep -f 'mininet:{h2}' | head -n1").read().strip()

	if not h1_pid or not h2_pid:
		print(f"\nOs processos dos hosts {h1} e {h2} não foram encontrados.")
		return

	print(f"PID de {h1} = {h1_pid}")
	print(f"PID de {h2} = {h2_pid}")

	# Inicia captura no h1
	print(f"\n*** Iniciando captura em {h2} -> {traffic_out}\n")
	os.system(f"mnexec -a {h2_pid} tcpdump src 10.0.0.5 -i {h2}-eth0 -w {traffic_out} &")
	time.sleep(2)

	# Executa tcpreplay no h0
	print(f"\n*** Iniciando reprodução de {traffic_in} em {h1}\n")
	def replay():
		os.system(f"mnexec -a {h1_pid} tcpreplay --intf1={h1}-eth0 -K --mbps {mbps} {traffic_in}")

	def break_link():
		
		for link in links:
			print(f"*** Derrubando o link {link}")
			net.configLinkStatus(*link, 'down')
			time.sleep(0.1)
									
	replay_thread = threading.Thread(target=replay)
	link_thread = threading.Thread(target=break_link)

	replay_thread.start()
	time.sleep(0.3)
	link_thread.start()

	replay_thread.join()
	link_thread.join()
	
	for link in links:
		print(f"*** Restabelecendo o link {link}")
		net.configLinkStatus(*link, 'up')    
		
	time.sleep(2)
	# Finaliza captura
	print(f"\n*** Encerrando captura em {h1}.")
	os.system(f"mnexec -a {h2_pid} pkill tcpdump")
	print(f"\n*** Tráfego capturado: {traffic_out}")
	
	response = requests.delete(f"{onos_host}/intents/org.onosproject.cli/{intent_id_hex}", auth=auth)
	if response.status_code == 204:
		print(f"Intent {intent_id_hex} desinstalado com sucesso.")
	else:
		print(f"Erro ao desinstalar o Intent: {response.status_code} - {response.text}")
	
	analyze_pcap(traffic_in, traffic_out, arquivo)

def analyze_pcap(pcap_in, pcap_out, nome_arquivo):

	nome_arquivo = "resultados4/" + nome_arquivo
	"""Analyze PCAP files."""
	print("\n*** Análise do tráfego.")

	try:

		#in_all = rdpcap(pcap_in)
		in_pkts = rdpcap(pcap_in)
		print("fim in_all")
		#out_all = rdpcap(pcap_out)
		out_pkts = rdpcap(pcap_out)
		print("fim out_all")
	except FileNotFoundError:
		print(f"\nOs arquivos {pcap_in} e {pcap_out} não foram encontrados.")
		return
		

	in_pkts = [pkt for pkt in in_all if pkt.haslayer(TCP)]
	out_pkts = [pkt for pkt in out_all if pkt.haslayer(TCP)]
	
	# Cálculo da perda de pacotes:

	n_sent = len(in_pkts)
	n_recv = len(out_pkts)
	n_lost = n_sent - n_recv

	print(f"\nPacotes (TCP) enviados: {n_sent}")
	print(f"Pacotes (TCP) recebidos: {n_recv}")
	print(f"Pacotes perdidos: {n_lost}")
	with open(nome_arquivo, "a") as f:
		f.write(f"pktsent:{n_sent}")
		f.write(f"\npktrecv:{n_recv}")
		f.write(f"\npktlost:{n_lost}")
	
	# Cálculo da largura de banda na saída:
	
	if n_recv > 0:
		t_first_out = float(out_pkts[0].time)
		t_last_out = float(out_pkts[-1].time)
		duration = float(t_last_out - t_first_out)
		total_bytes_out = sum(len(pkt) for pkt in out_pkts)
		avg_bw_out = (total_bytes_out * 8 / duration) / 1e6 if duration > 0 else 0
		
	else:
		duration = 0
		avg_bw_out = 0

	print(f"Largura de banda média: {avg_bw_out:.3f} Mbps")
	with open(nome_arquivo, "a") as f:
		f.write(f"\nbw:{avg_bw_out}")

	# Cálculo do Jitter:
	
	if n_recv > 1:
		interarrivals = [float(out_pkts[i].time) - float(out_pkts[i-1].time) for i in range(1, n_recv)]
		jitter = statistics.pstdev(interarrivals)
	else:
		jitter = 0

	print(f"Jitter: {jitter:.6f} s")
	with open(nome_arquivo, "a") as f:
		f.write(f"\njitter:{jitter:.6f}\n\n")
		
	print("\n*** Fim da análise (TCP).")

def main():
	
	# Criação da topologia:

	for app in apps_to_activate:
		activate_app(app)
	
	topo = GeneratedTopo()
	switch13 = partial(OVSSwitch, protocols='OpenFlow13')
	net = Mininet(
		topo=topo,
		switch=switch13,
		controller=None,
		autoSetMacs=True
	)

	c0 = net.addController(
		'c0',
		controller=RemoteController,
		ip='127.0.0.1',
		port=6633
	)

	info('\n*** Iniciando a rede...\n')
	net.start()
	
	time.sleep(5)
	info('\n*** Testando conectividade (pingall)\n')
	net.pingAll()

	deactivate_app("org.onosproject.fwd")

	try:
		while True:
			print("\nEscolha uma ação:")
			print("1. Executar teste de reprodução e captura de PCAPs")
			print("2. Sair")
			choice = input("Digite sua escolha: ")

			if choice == '1':
				velocidade = float(input("Velocidade da reprodução (em Mbps): "))
				arquivo = input("Nome do arquivo: ")
				for i in range(20):
					replay_capture(net, velocidade, arquivo)
			elif choice == '2':
				break
			else:
				print("Escolha inválida.")
	except KeyboardInterrupt:
		print("\nInterrompido pelo usuário.")
	finally:
		info('\n*** Parando a rede...\n')
		net.stop()

if __name__ == '__main__':
	setLogLevel('info')
	main()

