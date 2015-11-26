import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class DSS{

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException{

        //Input File
        int L = 512,N = 160;
        //0.q 1.p 2.seed
        BigInteger[] parameter_prime = new BigInteger[10];
        String secret_file = null,public_key = null,message_file = null,signature_file = null;
        BigInteger p = BigInteger.ZERO,q = BigInteger.ZERO,h = BigInteger.ZERO,g = BigInteger.ZERO,x = BigInteger.ZERO,y = BigInteger.ZERO,r = BigInteger.ZERO,s = BigInteger.ZERO,k = BigInteger.ZERO,w = BigInteger.ZERO,u1,u2,v = BigInteger.ZERO,hashedInput = BigInteger.ZERO;
        for(int i = 0 ; i <args.length; i++){
            if (args[i].equals("-p")){
                L = Integer.parseInt(args[i+1]);
            }
            if (args[i].equals("-q")){
                N = Integer.parseInt(args[i+1]);
            }
            if (args[i].equals("-S")){
                secret_file = args[i+1];
            }
            if (args[i].equals("-P")){
                public_key = args[i+1];
            }
            if (args[i].equals("-M")){
                message_file = args[i+1];
            }
            if (args[i].equals("-s")){
                signature_file = args[i+1];
            }
        }
    
        if(args.length >=8){
        	// randomly order the arguments is acceptable!!!
        	//java DSS -p <size_in_bits_of_p> -q <size_in_bits_q> -S <secret_key_file> -P <public_key_file>
        	//can change the order of the  argument
            if(args[0].equals("-p")||args[2].equals("-p")||args[4].equals("-p")||args[6].equals("-p")){
                if(args[0].equals("-q")||args[2].equals("-q")||args[4].equals("-q")||args[6].equals("-q")){
                    if(args[0].equals("-S")||args[2].equals("-S")||args[4].equals("-S")||args[6].equals("-S")){
                        if(args[0].equals("-P")||args[2].equals("-P")||args[4].equals("-P")||args[6].equals("-P")){
                        	DSS.init(L , N);
                        	parameter_prime = parameterPrimeGenerator(N, L, parameter_prime);
                            q = generateQ(N,parameter_prime);
                            p = generateP(L,q,parameter_prime);
                            g = generateG(p,q,parameter_prime);
                            x = generateX();
                            y = generateY(x,p,g);
                            try (Writer writer = new BufferedWriter(new OutputStreamWriter(
                                    new FileOutputStream(secret_file), "utf-8"))) {
                                writer.write("DSA Private Key:");
                                writer.write("\r\n");
                                writer.write("p = "+ p);
                                writer.write("\r\n");
                                writer.write("q = "+ q);
                                writer.write("\r\n");
                                writer.write("g = "+ g);
                                writer.write("\r\n");
                                writer.write("x = "+ x);
                            }
                            try (Writer writer = new BufferedWriter(new OutputStreamWriter(
                                    new FileOutputStream(public_key), "utf-8"))) {
                                writer.write("DSA Public Key:");
                                writer.write("\r\n");
                                writer.write("p = "+ p);
                                writer.write("\r\n");
                                writer.write("q = "+ q);
                                writer.write("\r\n");
                                writer.write("g = "+ g);
                                writer.write("\r\n");
                                writer.write("y = "+ y);
                            }
                            System.out.println("Files generated successfully");
                        }
                    }
                }
            }
        }
        if(args.length>=6){
        	//java DSS -M messagefile -S secret_key_file -s signature_file
            if(args[0].equals("-M")||args[2].equals("-M")||args[4].equals("-M")){
                if(args[0].equals("-S")||args[2].equals("-S")||args[4].equals("-S")){
                    if(args[0].equals("-s")||args[2].equals("-s")||args[4].equals("-s")){
                        String M = readMessage(new File(message_file));
                        hashedInput = SHA1(M);
                        try{
                            BufferedReader in = new BufferedReader(new FileReader(secret_file));
                            String data_txt;
                            while((data_txt = in.readLine()) != null) {
                                if(data_txt.contains("p = ")) {
                                    p = p.add(new BigInteger(data_txt.split(" = ")[1]));
                                }
                                if(data_txt.contains("q = ")) {
                                    q = q.add(new BigInteger(data_txt.split(" = ")[1]));
                                }
                                if(data_txt.contains("g = ")) {
                                    g = g.add(new BigInteger(data_txt.split(" = ")[1]));
                                }
                                if(data_txt.contains("x = ")) {
                                    x = x.add(new BigInteger(data_txt.split(" = ")[1]));
                                }
                            }
                            signFile(signature_file,M,hashedInput,p,q,g,x);
                        }catch (FileNotFoundException ex){
                            System.out.println("Can not find secret key file");
                        }
                    }
                }
            }
            if(args[0].equals("-M")||args[2].equals("-M")||args[4].equals("-M")){
            	//java DSS -M messagefile -P public_key_file -s signature_file
                if(args[0].equals("-P")||args[2].equals("-P")||args[4].equals("-P")){
                    if(args[0].equals("-s")||args[2].equals("-s")||args[4].equals("-s")){
                        try{
                            String M = readMessage(new File(message_file));
                            hashedInput = SHA1(M);
                            BufferedReader in = new BufferedReader(new FileReader(public_key));
                            String data_txt;
                            while((data_txt = in.readLine()) != null) {
                                if(data_txt.contains("p = ")) {
                                    p = p.add(new BigInteger(data_txt.split(" = ")[1]));
                                }
                                if(data_txt.contains("q = ")) {
                                    q = q.add(new BigInteger(data_txt.split(" = ")[1]));
                                }
                                if(data_txt.contains("g = ")) {
                                    g = g.add(new BigInteger(data_txt.split(" = ")[1]));
                                }
                                if(data_txt.contains("y = ")) {
                                    y = y.add(new BigInteger(data_txt.split(" = ")[1]));
                                }
                            }
                            System.out.println("Verifying message:"+verifySignature(s,r,q,p,g,y,hashedInput));
                        }catch (FileNotFoundException ex){
                            System.out.println("Can not find signed file");
                        }
                    }
                }
            }
        }else{
            System.out.println("Invalid Command");
        }
        System.out.println("Program end");
    }

    public static BigInteger generateQ(int N, BigInteger[] parameter_prime){
        BigInteger q = BigInteger.probablePrime(N,new Random());
        return parameter_prime[0];
    }

    public static BigInteger generateP(int L, BigInteger q, BigInteger[] parameter_prime){
        BigInteger p,tmp;
        do {
            p = new BigInteger(L, new Random());
            tmp = p.subtract(BigInteger.ONE);
            p = p.subtract(tmp.remainder(q));
        } while ((!p.isProbablePrime(80) || p.bitLength() != L));
        return parameter_prime[1];
    }

    public static BigInteger generateG(BigInteger p, BigInteger q, BigInteger[] parameter_prime)throws NoSuchAlgorithmException{
        /*BigInteger h,g;
        do{
            h = BigInteger.ONE;
            BigInteger two = new BigInteger("2");
            g = two.modPow(p.subtract(BigInteger.ONE).divide(q), p);
        }while(g.equals(BigInteger.ONE));*/
        return generator(parameter_prime[2].toByteArray(),p,q);
    }
    public static BigInteger generateX(){
        return new BigInteger(100, new Random());
    }
    public static BigInteger generateY(BigInteger x, BigInteger p, BigInteger g){
        return g.modPow(x, p);
    }

    public static String readMessage(File Message_file)throws IOException{
        String M= "";
        try{
            BufferedReader in = new BufferedReader(new FileReader(Message_file));
            String M1="",m_line;
            while((m_line = in.readLine()) != null) {
                M1 = M1+m_line;
            }
            M = M+M1;
        }
        catch(FileNotFoundException ex){
            System.out.println("Can not find message file");
            //ex.printStackTrace();
        }
        return M;
    }

    public static void signFile(String signature, String M,BigInteger hashedInput, BigInteger p, BigInteger q, BigInteger g, BigInteger x)throws NoSuchAlgorithmException, IOException{
        BigInteger k,r,s;
        k = new BigInteger(50, new Random());
        r = g.modPow(k, p).mod(q);
        s = k.modInverse(q).multiply(hashedInput.add(x.multiply(r))).mod(q);
        while (r.compareTo(BigInteger.ZERO) == 0 || s.compareTo(BigInteger.ZERO) == 0) {
            k = new BigInteger(50, new Random());
            r = g.modPow(k, p).mod(q);
            s = k.modInverse(q).multiply(hashedInput.add(x.multiply(r))).mod(q);
        }

        try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(signature), "utf-8"))) {
            writer.write("DSASignature:");
            writer.write("\r\n");
            writer.write("k = "+ k);
            writer.write("\r\n");
            writer.write("r = "+ r);
            writer.write("\r\n");
            writer.write("s = "+ s);
            writer.write("\r\n");
        }
        System.out.println("Message Signed Successfully");
    }
    public  static  boolean verifySignature(BigInteger s, BigInteger r, BigInteger q, BigInteger p, BigInteger g, BigInteger y, BigInteger hashedInput){
        if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0) {
            return false;
        }
        if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(q) >= 0) {
            return false;
        }
        BigInteger result,w,u1,u2;
        w = s.modInverse(q);
        u1 = hashedInput.multiply(w).mod(q);
        u2 = r.multiply(w).mod(q);
        result = ((g.modPow(u1, p).multiply(y.modPow(u2, p))).mod(p)).mod(q);
        if(result.compareTo(r) == 0){
            return true;
        }else{
            return false;
        }
    }
    /**
     * generate suitable parameters for DSA, in line with
     * <i>FIPS 186-3 A.1 Generation of the FFC Primes p and q</i>.
     * p is parameter_prime[1]
     * q is parameter_prime[0]
     * seed is parameter_prime[2]
     */
    public static BigInteger[] parameterPrimeGenerator(int N, int L, BigInteger[] parameter_prime) throws NoSuchAlgorithmException{
    	// A.1.1.2 Generation of the Probable Primes p and q Using an Approved Hash Function
        // FIXME This should be configurable (digest size in bits must be >= N)
    	BigInteger p,q;
        MessageDigest d = MessageDigest.getInstance("SHA-1");
        int outlen = d.digest().length * 8;

     // 2. If (seedlen < N), then return INVALID.
     // FIXME This should be configurable (must be >= N)
        int seedlen = N;
        byte[] seed = new byte[seedlen/8];
     // 3. n = ceiling(L / outlen) - 1.
        int n = (L -1) / outlen;
     // 4. b = L - 1 - (n * outlen).
        int b = (L-1) % outlen;
        byte[] w = new byte[L / 8];
        SecureRandom random = new SecureRandom();

        for(;;){
    // 5. Get an arbitrary sequence of seedlen bits as the domain_parameter_seed.
            random.nextBytes(seed);
            d.update(seed);
         // 6. U = Hash (domain_parameter_seed) mod 2^(N–1).
            BigInteger U = new BigInteger(1,d.digest()).mod(BigInteger.ONE.shiftLeft(N - 1));
         // 7. q = 2^(N–1) + U + 1 – ( U mod 2).
            q = U.setBit(0).setBit(N-1);

            if(!q.isProbablePrime(80)){
                continue;
            }
            parameter_prime[0] = q;
            int offset = 1;

            int countLimit = 4*L;
            for (int counter=0 ; counter < countLimit ; ++counter)
            {
         // 11.1 For j = 0 to n do
         //  Vj = Hash ((domain_parameter_seed + offset + j) mod 2^seedlen).
        // 11.2 W = V0 + (V1 ∗ 2^outlen) + ... + (V^(n–1) ∗ 2^((n–1) ∗ outlen)) + ((Vn mod 2^b) ∗ 2^(n ∗ outlen)).
                offset += counter*n;
                {
                    for(int j = 1 ; j <= n ; ++j){
                        offset +=1;
                        int temp = toInt(seed);
                        temp += offset;
                        temp += j;
                        byte[] tempseed = toByteArray(temp,seedlen);
                        d.update(tempseed);
                        System.arraycopy(d.digest(), 0 , w ,w.length - j*d.digest().length,d.digest().length);
                    }

                    int remaining = w.length - (n*d.digest().length);
                    int j = 7;
                    int temp = toInt(seed);
                    temp += offset;
                    temp += j;
                    byte[] tempseed = toByteArray(temp,N);
                    d.update(tempseed);
                    System.arraycopy(d.digest(),d.digest().length - remaining, w , 0 ,remaining);

                }
             // 11.3 X = W + 2^(L–1). Comment: 0 ≤ W < 2^(L–1); hence, 2^(L–1) ≤ X < 2^L.
                w[0] |= (byte)0x80;
                BigInteger X = new BigInteger(1,w);
             // 11.4 c = X mod 2q
                BigInteger c = X.mod(q.shiftLeft(1));

             // 11.5 p = X - (c - 1). Comment: p ≡ 1 (mod 2q).
                p = X.subtract(c.subtract(BigInteger.ONE));
                if (p.bitLength() != L)
                {
                    continue;
                }

                if (p.isProbablePrime(80))
                {
                	parameter_prime[2] = new BigInteger(seed);
                    parameter_prime[1]=p;
                    return parameter_prime;
                }
            }
        }
    }
    public static void init(int L , int N){
    	// 1. Check that the (L, N) pair is in the list of acceptable (L, N pairs) (see Section 4.2). If
//      the pair is not in the list, then return INVALID.
          // Note: checked at initialisation
        if ((L < 1024 || L > 3072) || L % 1024 != 0)
        {
            throw new IllegalArgumentException("L values must be between 1024 and 3072 and a multiple of 1024");
        }
        else if (L == 1024 && N != 160)
        {
            throw new IllegalArgumentException("N must be 160 for L = 1024");
        }
        else if (L == 2048 && (N != 224 && N != 256))
        {
            throw new IllegalArgumentException("N must be 224 or 256 for L = 2048");
        }
        else if (L == 3072 && N != 256)
        {
            throw new IllegalArgumentException("N must be 256 for L = 3072");
        }
  	          
    }

    public static BigInteger generator(byte[] seed, BigInteger p, BigInteger q) throws NoSuchAlgorithmException{
    	// A.2.3 Verifiable Canonical Generation of the Generator g
    	
    	SecureRandom random = new SecureRandom();
        MessageDigest d = MessageDigest.getInstance("SHA-1");
        BigInteger e = (p.subtract(BigInteger.ONE)).divide(q);
        byte[] ggen = decodeHex("6767656E".toCharArray());
        byte[] index = new byte[1];
        random.nextBytes(index);

     // 7. U = domain_parameter_seed || "ggen" || index || count.
        byte[] U = new byte[seed.length+ggen.length+1+2];
        System.arraycopy(seed, 0, U, 0, seed.length);
        System.arraycopy(ggen,0,U,seed.length,ggen.length);

        U[U.length-3] = index[0];

        byte[] w = new byte[d.digest().length];

        for (int count = 1 ; count < (1<<16) ; ++count){
            int temp = toInt(U);
            temp += count;
            byte[] tempseed = toByteArray(temp,U.length);
            d.update(tempseed);
            w = d.digest();
            //8. W = Hash(U).
            //9. g = We mod p. 
            BigInteger W = new BigInteger(1, w);
            BigInteger g = W.modPow(e, p);
            
            //10. If (g < 2), then go to step 5. Comment: If a generator has not been found. 
            if (g.compareTo(BigInteger.valueOf(2)) >= 0)
            {
                return g;
            }

        }
        return null;
    }

    public static byte[] toByteArray(int iSource, int iArrayLen) {
    	//covert int to an byte array
        byte[] bLocalArr = new byte[iArrayLen];
        for (int i = 0; (i < 4) && (i < iArrayLen); i++) {
            bLocalArr[i] = (byte) (iSource >> 8 * i & 0xFF);
        }
        return bLocalArr;
    }

    public static int toInt(byte[] bRefArr) {
    	//covert a byte array to a int 
        int iOutcome = 0;
        byte bLoop;

        for (int i = 0; i < bRefArr.length; i++) {
            bLoop = bRefArr[i];
            iOutcome += (bLoop & 0xFF) << (8 * i);
        }
        return iOutcome;
    }

    protected static int toDigit(char ch, int index) {
    	//covert hexadecimal to digit
        int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new RuntimeException("Illegal hexadecimal character " + ch
                    + " at index " + index);
        }
        return digit;
    }

    public static byte[] decodeHex(char[] data) {
    	//covert hexadecimal to byte array
        int len = data.length;

        if ((len & 0x01) != 0) {
            throw new RuntimeException("Odd number of characters.");
        }

        byte[] out = new byte[len >> 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            int f = toDigit(data[j], j) << 4;
            j++;
            f = f | toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }

    public static BigInteger SHA1(String M) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(M.getBytes());
        BigInteger hashedInput = new BigInteger(sha1.digest());
        return hashedInput;
    }
}