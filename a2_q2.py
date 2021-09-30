from math import exp, log10
import random

# The following code was implemented with the guidance of
# the steps shown in http://practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/

# Generate the ngram statistics given a gile
def get_grams(gram_file):
    grams = {}
    n = 0
    with open(gram_file) as f:
        for line in f:
            gram, count = line.split(" ")
            grams[gram] = int(count)
            n += int(count)
    for k, v in grams.items():
        grams[k] = log10(v*1.0/n)
    
    # tutorial says not to use -inf for log(0) so use the
    # log of an arbitrarily small value over n
    return grams, log10(0.1/n)

quad_grams, quad_zero = get_grams('english_quadgrams.txt')
quint_grams, quint_zero = get_grams('english_quintgrams.txt')
tri_grams, tri_zero = get_grams('english_trigrams.txt')

# Get the fitness score for an ngram
def get_n_fitness(gram_prob, n, zero, text):
    fitness = 0
    for i in range(len(text) - n):
        if i + n >= len(text):
            break
        gram = text[i:i + n]
        if gram in gram_prob:
            fitness += gram_prob[gram]
        else:
            fitness += zero
    return fitness

# Get the overall fitness score
def get_fitness(text):
    upper_text = text.upper()
    # Using multiple ngram scores makes the score more accurate
    fitness_sum = get_n_fitness(quad_grams, 4, quad_zero, upper_text) + get_n_fitness(quint_grams, 5, quint_zero, upper_text) + get_n_fitness(tri_grams, 3, tri_zero, upper_text)
    # Found that multiplying by 0.08 generates better df/t probabilities to makes
    # the algorithm faster
    return (fitness_sum/3.0)*0.08

# Decrypt a playfair cipher given a key
def decrypt(key, cipher):
    # make 5x5 key square
    key_sqr = []
    loc_tracker = {}
    for i in range(5):
        curr = []
        for j in range(5):
            curr.append(key[(i*5)+j])
            loc_tracker[key[(i*5)+j]] = (i, j)
        key_sqr.append(curr)

    # split cipher into pairs
    cipher_pairs = []
    i = 0
    while i < len(cipher):
        first = cipher[i]
        second = cipher[i+1]
        cipher_pairs.append((first, second))
        i += 2

    # decrpyt to plain text
    plain_pairs = []
    for first, second in cipher_pairs:
        f_x, f_y = loc_tracker[first]
        s_x, s_y = loc_tracker[second]

        if f_y == s_y:
            plain_pair = key_sqr[(f_x-1) % 5][f_y], key_sqr[(s_x-1) % 5][s_y]
        elif f_x == s_x:
            plain_pair = key_sqr[f_x][(f_y-1) % 5], key_sqr[s_x][(s_y-1) % 5]
        else:
            plain_pair = key_sqr[f_x][s_y], key_sqr[s_x][f_y]

        plain_pairs.append(plain_pair)

    plain_text = []
    for first, second in plain_pairs:
        plain_text.append(first)

        # Adding this step makes the fitness score be more accurate
        if second != 'x':
            plain_text.append(second)

    return "".join(plain_text)


# The following code was implemented with the guidance of
# the steps shown in http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-playfair/
def solve(start_key=""):
    cipher_text = "IECZGNEFAUZICYNYTKDWZNVEEOTERXNRWECUSGIEIYCYEAKWKREBDWWXKWVRHDNWMHNRXRQGQRZVNBYNRVIRNWNCFTNMZIVYSAKRMHRINRCUHAIORKCYFHFRQGVREOHWMFXGCEHVDWZAGNSQYNNZHDWTBIWLDWONBEZNCMHCUFDWZAVECZIRDWOEEXHDNWDRYNVYNCHRUCSWBNFBGROTIVKRIWDWRCCFXRRKCYFNWVYNVOKWKREBDWWMZKMCDWOBUFVEFCFNOEEGFPRCKRIHBEIEIYCYNRNYTKIEIYCYKXMFFRQGQWRCVEQBWDCFDWOEXCAVZICYEAHTMLCWYXCFIEIYCYTXBIHQACRVDWOBUFVELEWVSGKRCUDRYNGEUCIXXBRKGQIVIRNWNCDWOCEHRAIETZWVOCIKHCNRVYTDAMZICYXIZHIOEFXNCRTDNRWSWVZOBQHCNRTOKITBACWXYXCFDWZAVECZIRYVNGVCRWOERCNRDTOAZNEAQREWAVNRLYEOYHRIFTIVEKOEDWOEEXHDNWIWDWRCEWNCNBZHIEQGVHRIVYFYHPRIUQIWDWRCCFXRRKCYFHRCIRXRODXTDWFTNYAOEAVTFRKYVZPHRXBNHUNWMHIOEFNRUNCEEOVWVYFYNYABXITDNRCACUEOVYTDWPRIKREBDWWAYNDWCFFKLAFZCEEHZNUHWXHMNRWAGNVOVWFBLADWWCHNRVTKFECHRIUIRANRHCNRNMWECVEBYHCMUZNBKTHCEXFRNBEAHTBFNBKRNCTDRINRFMVRIXDWOEEXKWKRCUHVOARVNRAXFZUGUXRVIRVEFGHURFOEIRNRSQFTTMVYYXCFKRDRSWKTVHMWBIAXFQWEBIHVDWRNBFCEFPRVDWRCCFXRRKCYHVRITKEFIDFEARFEQBNTZICYEOQSCOHDNRNMWECVEBATNROELIFGSGKRCTWSCEKTFYHMILNOHRUCNHDTXAIEIYCYXZIQFEATZICYEAHDNWCUHYSWCXUYIKLAIRBRIRYNDFUTXIZHZIOZEWCFHPRIRFIEIYCYMFOACVZICYNYTKDWRCCFXRRKCYHVRIUQCIZICYXNCREWFGNUZICYZEXCFHWECARIDWOZZNIWDWCFYLCFDWRABEHQKRDWENZABIEAXMLVMUEOHDNRNMWECVEBRHRIFEIEIYCYPZNRWVMFLQUCOAZCDMAMZICYEAHYOERVDWRAIORKCYHVRIUQIRAVOCNWQREWCFNMZICYEAVWNRWECWSHZFEIZICYNWKCLADTCOHDNRUZRINTZICYMFFRQGPTMIWTWCNRTWENCENRWEDHRIEAHRSWMFDWWCYNVOHDNRNMWECVEBRHRITXUFHUBNSGBIPZHMBEAMZICYEAHDNRSABIXTFGFQFERHRIFZIEIYCYRWUFRCNRWAOERAGNFKLADWEBQBWDNRXIEOHMIEIYCYDWRCCFXRRKCYHCBFHDNRXIFGFBXTLAHMBEXMAXLZBEHCNRFZFENXXRRKCYHAFRTNZKVZKWKRAHDTOAZNCFDWONBEZNCWHVFZHQDWRAIORKXIEWFUKCLAKRDRNRFCWBRAMQIEIYCYUCIOBZCVYCCEXRRKTNZKVZETZICYEAVWHIOEPZNXDWOEKTRVUCIOIFVEEOIXPZBFPTRINREWHSEFYXFYHNBNCKRVKRIWDWCAUTWVBCSPZPCFHDNWCUFHCRWVIXFUKCLAGNEFOCXRQGPTWEZWIEIYCYFZDWWCUTUXWDFEURCVZIBNEFBNWPRIDWOERAYNEFOBHINRTMAVFDCFXUBHHYFRAXFYFZZOGCCULIHUNWCUFZEFWBRAIRFBNCNRTRUCNWFGSUWSCETDKRMHNRIEIYCYEFNRZDWECIZICYDZZIMFRVIRCYOWZWCZYNFZEFYNUIBIHQCEEHCABIWLIZACWMBZMUHQGERCCRTWBINZXITWOEFZMFRCIRXRODNWTHOEDWEACNOEKRURMCDWBATOFGFUNCHRUCNWFEHQXRCYHAFRKTVHRIAXHCNRTDZIWEZWEAXZACIEIYCYXIZHNRAXFYFZNGMZHNRAMFNRHDNRXUBHIREOCYCFXTDWNREWHVKRDWCVIOIFCFYXHVDWRNBINZXRODKRMHRINRBFHRZIEAARHCIRDWRAUIVOHRUCTNIXDWOACEHMIEIYCYEAVDEBTUNZHWOEDRZFNRZVEAVWIEXTLHNRXRQGVDEONCHCDWZCWEOTXYRVRIDWOEBCKZHCNRXTIVRVXTCINRAVNWHCRVPZXGCVZICYEAHRNRFCAXNMFRKYKMLAXAXWWCPZZOHMEFRVXWIEIYCYXIOTAXNYFAKIMLIRABIWDWCARAFRMLCEHVPZXTNOYNFZEFYNKZFYFMUGCVZICYDWCEAOHSMKVZVWFGNGIRAVCEHVIMIRXOSIGSONUHBAKRIWDWMFWCXKZHMHOAZCRVXYEOWCTUHLBECMACIEIYCYXIOTVFRAXEACNBYGABPTEAIEQGVHRIKRNCZWARFGNGNYXRRKTNZKVZTHRIFZTXCAIWIRWCCFYPUCNWHVNWHWUTCYVOCZEARANBXBMCIXCUFA".lower()
    chars = "abcdefghiklmnopqrstuvwxyz"

    parent = random.sample(chars, 25) if not start_key else [c for c in start_key]
    parent_fitness = get_fitness(decrypt(parent, cipher_text))
    print(decrypt(parent, cipher_text))
    max_fitness = parent_fitness
    max_key = "".join

    t = 18
    step = 0.2
    while t >= 0:
        for count in range(10000):
            # swap two random letters in the key
            first = random.randint(0, 24)
            second = random.randint(0, 24)
            while first == second:
                second = random.randint(0, 24)

            parent[first], parent[second] = parent[second], parent[first]
            child = parent
            plaintext = decrypt(child, cipher_text)
            child_fitness = get_fitness(plaintext)
            df = child_fitness - parent_fitness
            if df >= 0:
                parent_fitness = child_fitness
            else:
                prob = exp(df/t)
                if count % 500 == 0:
                    print("prob: " + str(prob) + " count: " + str(count) + " t: " + str(t) + " fitness: " + str(parent_fitness))

                if prob > random.random():
                    parent_fitness = child_fitness
                else:
                    parent[first], parent[second] = parent[second], parent[first]

            if parent_fitness > max_fitness:
                max_fitness = parent_fitness
                max_key = "".join(parent)
                print(plaintext)
                print(max_fitness)
                print(max_key)

        t -= step

    return max_fitness, max_key

print(solve())
