import requests, zipfile, os, shutil, glob, yara

def create(folder):
        if not os.path.exists(folder):
                os.mkdir(folder)

def copyfiles(src, dst):
        for root, dirs, files in os.walk(src):
            for filename in files:
                if ('.yara' in filename or '.yar' in filename):
                    shutil.copy(os.path.join(root, filename), os.path.join(dst, filename))

def unzip(filename, dst):
	with zipfile.ZipFile(filename, 'r') as zip_ref:
		zip_ref.extractall(dst)

def download(dst, path):
	r = requests.get(path)
	open(dst, 'wb').write(r.content)

def compile(filepaths, save_folder):
	compiled_rules = dict()
	for folder in filepaths:
		for filename in glob.glob(folder + '/*.yar*'):
			namespace = os.path.basename(os.path.splitext(filename)[0])
#compiled_rules[namespace] = os.path.abspath(filename)
			compiled_rules[namespace] = os.path.abspath(filename)

			print("Reglas que se van a compilar:")
			for ns, path in compiled_rules.items():
    				print(f"Namespace: {ns} -> {path}")

	rules = yara.compile(filepaths = compiled_rules)
	print(compiled_rules)
	if os.path.exists(save_folder):
		os.remove(save_folder)
	rules.save(save_folder)

# ===== RUTAS Y VARIABLES =====

root = os.path.dirname(os.path.abspath(__file__))
compiled_rules = os.path.join(root, "yara_rules", "rules-compiled")

# CAPEv2
cape_filename = os.path.join(root, 'CAPEv2.zip')
capev2_folder = os.path.join(root, 'CAPEv2-master')
yara_cape_folder = os.path.join(capev2_folder, 'data', 'yara', 'CAPE')
local_cape_folder = os.path.join(root, 'yara_rules', 'Cape')

# ReversingLabs
reversinglabs_filename = os.path.join(root, 'reversinglabs-yara-rules.zip')
reversinglab_folder = os.path.join(root, 'reversinglabs-yara-rules-develop')
yara_reversinglab_folder = os.path.join(reversinglab_folder, 'yara')
local_reversinglabs_folder = os.path.join(root, 'yara_rules', 'ReversingLabs')

# Neo23x0 Signature-Base (master)
neo_filename = os.path.join(root, 'signature-base.zip')
neo_folder = os.path.join(root, 'signature-base-master')
yara_neo_folder = os.path.join(neo_folder, 'yara')
local_neo_folder = os.path.join(root, 'yara_rules', 'Neo23x0')

# ========== PROCESO DE CADA FUENTE ==========

# CAPEv2
create(local_cape_folder)
download(dst=cape_filename, path='https://codeload.github.com/kevoreilly/CAPEv2/zip/refs/heads/master')
unzip(filename=cape_filename, dst=root)
shutil.copytree(src=yara_cape_folder, dst=local_cape_folder, dirs_exist_ok=True)
shutil.rmtree(capev2_folder)
os.remove(cape_filename)

# ReversingLabs
create(local_reversinglabs_folder)
download(dst=reversinglabs_filename, path='https://codeload.github.com/reversinglabs/reversinglabs-yara-rules/zip/refs/heads/develop')
unzip(filename=reversinglabs_filename, dst=root)
copyfiles(src=yara_reversinglab_folder, dst=local_reversinglabs_folder)
shutil.rmtree(reversinglab_folder)
os.remove(reversinglabs_filename)


import os

def remove_unwanted_file(file_to_remove):
    if os.path.exists(file_to_remove):
        os.remove(file_to_remove)
        print(f"Archivo eliminado: {file_to_remove}")
    else:
        print(f"El archivo {file_to_remove} no existe.")


# Neo23x0
create(folder=local_neo_folder)
download(dst=neo_filename, path='https://codeload.github.com/Neo23x0/signature-base/zip/refs/heads/master')
unzip(filename=neo_filename, dst=root)
copyfiles(src=yara_neo_folder, dst=local_neo_folder)
shutil.rmtree(neo_folder)
os.remove(neo_filename)

# Ruta del archivo a eliminar
file_to_remove = '/home/osboxes/yara_rules/Neo23x0/gen_fake_amsi_dll.yar'
remove_unwanted_file(file_to_remove)
file_to_remove = '/home/osboxes/yara_rules/Neo23x0/yara_mixed_ext_vars.yar'
# Llamar a la función para eliminar el archivo no deseado
remove_unwanted_file(file_to_remove)



# ========== COMPILAR TODAS LAS REGLAS ==========
directories = [local_cape_folder, local_reversinglabs_folder, local_neo_folder]
compile(filepaths=directories, save_folder=compiled_rules)

 
