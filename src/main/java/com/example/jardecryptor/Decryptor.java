package com.example.jardecryptor;

import java.io.*;
import java.lang.reflect.Method;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.util.jar.*;
import java.security.*;

public class Decryptor {

    public static void main(String[] args) {
        try {

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String a = reader.readLine();

            if (a == null || a.isEmpty()) {

                return;
            }

            byte[] b = Base64.getDecoder().decode(a);
            SecretKey secretKey = new SecretKeySpec(b, "AES");


            try (InputStream encryptedStream = Decryptor.class.getResourceAsStream("/Moodle1.jar.enc")) {
                if (encryptedStream == null) {

                    return;
                }

                ByteArrayOutputStream decryptedJarStream = decryptJarFileToMemory(encryptedStream, secretKey);

                executeJarFromMemory(decryptedJarStream.toByteArray());

            }
        } catch (Exception e) {

            e.printStackTrace();
        }
    }


    private static ByteArrayOutputStream decryptJarFileToMemory(InputStream encryptedStream, SecretKey secretKey) throws Exception {
        byte[] iv = encryptedStream.readNBytes(16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        try (CipherInputStream cis = new CipherInputStream(encryptedStream, cipher);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[16384];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }

            return outputStream;
        }
    }

    private static void executeJarFromMemory(byte[] jarBytes) throws Exception {
        InMemoryClassLoader classLoader = new InMemoryClassLoader(jarBytes);
        Thread.currentThread().setContextClassLoader(classLoader);

        String mainClassName = classLoader.getMainClassName();
        if (mainClassName == null) {
            throw new RuntimeException("Classe principale non définie dans le manifest.");
        }


        Class<?> mainClass = classLoader.loadClass(mainClassName);
        Method mainMethod = mainClass.getMethod("main", String[].class);
        mainMethod.invoke(null, (Object) new String[]{});
    }

    static class InMemoryClassLoader extends ClassLoader {
        private final Map<String, byte[]> classBytes = new HashMap<>();
        private final Map<String, byte[]> resources = new HashMap<>();
        private final List<File> tempFiles = Collections.synchronizedList(new ArrayList<>());
        private final Map<String, File> resourceFiles = new HashMap<>();
        private final List<FileInputStreamWithDelete> openStreams = Collections.synchronizedList(new ArrayList<>());
        private final Manifest manifest;

        public InMemoryClassLoader(byte[] jarBytes) throws IOException {
            super(InMemoryClassLoader.class.getClassLoader());

            try (JarInputStream jisForManifest = new JarInputStream(new ByteArrayInputStream(jarBytes))) {
                this.manifest = jisForManifest.getManifest();
            }

            try (JarInputStream jarInputStream = new JarInputStream(new ByteArrayInputStream(jarBytes))) {
                JarEntry entry;
                while ((entry = jarInputStream.getNextJarEntry()) != null) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[2048];
                    int len;
                    while ((len = jarInputStream.read(buffer)) != -1) {
                        baos.write(buffer, 0, len);
                    }

                    byte[] data = baos.toByteArray();
                    if (entry.getName().endsWith(".class")) {
                        String className = entry.getName().replace('/', '.').replace(".class", "");
                        classBytes.put(className, data);
                    } else {
                        resources.put(entry.getName(), data);
                    }
                }
            }


            Runtime.getRuntime().addShutdownHook(new Thread(this::cleanup));
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] bytes = classBytes.get(name);
            if (bytes == null) {
                return super.findClass(name);
            }

            int lastDot = name.lastIndexOf('.');
            if (lastDot != -1) {
                String packageName = name.substring(0, lastDot);
                if (getPackage(packageName) == null) {
                    definePackage(packageName, null, null, null, null, null, null, null);
                }
            }

            return defineClass(name, bytes, 0, bytes.length);
        }


        @Override
        public InputStream getResourceAsStream(String name) {
            String fixedName = name.startsWith("/") ? name.substring(1) : name;
            byte[] data = resources.get(fixedName);
            if (data != null) {
                return new ByteArrayInputStream(data);
            }
            return super.getResourceAsStream(name);
        }


        @Override
        protected URL findResource(String name) {
            String fixedName = name.startsWith("/") ? name.substring(1) : name;
            if (resources.containsKey(fixedName)) {
                try {
                    File tempFile = resourceFiles.get(fixedName);
                    if (tempFile == null || !tempFile.exists()) {
                        tempFile = File.createTempFile("resource_", ".tmp");
                        tempFile.deleteOnExit();
                        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                            fos.write(resources.get(fixedName));
                        }
                        tempFiles.add(tempFile);
                        resourceFiles.put(fixedName, tempFile);
                    }
                    return tempFile.toURI().toURL();
                } catch (IOException e) {

                }
            }
            return super.findResource(name);
        }

        public void cleanup() {
            closeAllStreams();
            for (File f : tempFiles) {
                if (f.exists() && !f.delete()) {

                }
            }
        }

        public void closeAllStreams() {
            for (FileInputStreamWithDelete fis : openStreams) {
                try {
                    fis.close();
                } catch (IOException e) {

                }
            }
            openStreams.clear();
        }

        public String getMainClassName() {
            if (manifest == null) return null;
            Attributes attributes = manifest.getMainAttributes();
            return attributes.getValue("Main-Class");
        }

        static class FileInputStreamWithDelete extends FileInputStream {
            private final File file;

            public FileInputStreamWithDelete(File file) throws IOException {
                super(file);
                this.file = file;
            }

            @Override
            public void close() throws IOException {
                super.close();
                if (file.exists() && !file.delete()) {

                }
            }
        }
    }
}
