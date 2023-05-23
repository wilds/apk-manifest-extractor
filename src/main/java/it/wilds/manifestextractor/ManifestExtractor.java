package it.wilds.manifestextractor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import com.fasterxml.jackson.databind.ObjectMapper;


public class ManifestExtractor {

    protected final static Logger logger = Logger.getLogger(ManifestExtractor.class.getSimpleName());

    public final static String APP_NAME = "manifest-extractor";

    protected final static String tempFolder = Paths.get("").toAbsolutePath().toString() + "/tmp";

    static {
        System.setProperty("java.util.logging.SimpleFormatter.format", "[%1$tF %1$tT] [%4$-12s] %5$s %n");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
        System.setProperty("org.eclipse.jetty.util.log.class", "org.eclipse.jetty.util.log.StdErrLog");
        System.setProperty("org.eclipse.jetty.LEVEL", "OFF");

        try {
            Files.createDirectories(Paths.get(tempFolder));
        } catch (IOException ex) {

        }
    }

    public static void main(String[] args) throws Exception {
        Options options = new Options();

        options.addOption(Option.builder("i").longOpt("input").hasArgs().argName("file").desc("input file").type(String.class).build());
        //options.addOption(Option.builder("o").longOpt("output").hasArgs().argName("file").desc("output file").type(String.class).build());

        options.addOption(Option.builder("ow").longOpt("overwrite").desc("overwrite").build());
        options.addOption(Option.builder("hn").longOpt("hashfilename").desc("hash file names").build());

        options.addOption(Option.builder("l").longOpt("log").hasArg().argName("level").desc("set info level: SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST").type(String.class).build());
        //options.addOption(Option.builder("lf").longOpt("log-file").hasArg().argName("file").desc("set log file").type(String.class).build());

        options.addOption("h", "help", false, "print usage");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (UnrecognizedOptionException ex) {
            System.err.println(ex.getMessage());
            HelpFormatter formatter = new HelpFormatter();
            formatter.setLongOptSeparator("=");
            formatter.printHelp(APP_NAME, options);
            return;
        }

        if (cmd.hasOption("help")) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.setLongOptSeparator("=");
            formatter.printHelp(APP_NAME, options);
            return;
        }

        //String logFile = cmd.hasOption("log-file") ? cmd.getOptionValue("log-file").trim() : null;

        Level infoLevel;
        try {
            infoLevel = cmd.hasOption("log") ? Level.parse(cmd.getOptionValue("log").trim()) : Level.INFO;
        } catch(IllegalArgumentException ex) {
            infoLevel = Level.INFO;
        }

        Logger root = Logger.getLogger("");
        root.setLevel(infoLevel);
        for (Handler handler : root.getHandlers()) {
            handler.setLevel(infoLevel);
        }

        boolean overwrite = cmd.hasOption("overwrite");
        boolean hashfilename = cmd.hasOption("hashfilename");

        byte[] buffer = new byte[1024];

        String[] files = cmd.getOptionValues("input");

        for (String file : files) {
            try (Stream<Path> paths = Files.walk(Paths.get(file))) {
                paths.forEach(f -> {

                    try {
                        String outFilename = (hashfilename ? sha256Hex(FilenameUtils.getName(f.toString()))
                                : FilenameUtils.getName(FilenameUtils.removeExtension(f.toString()))) + ".json";
                        File outfile = new File(outFilename);
                        if (outfile.exists() && !overwrite) {
                            return;
                        }

                        if ("apk".equalsIgnoreCase(FilenameUtils.getExtension(f.toString()))) {
                            logger.info("Read manifest of " + f.toString());
                            Map<String, Object> manifest = getAPKManifest(f.toString());
                            addMetadata(manifest, f);
                            expandIcon(manifest, f);

                            ObjectMapper objectMapper = new ObjectMapper();
                            objectMapper.writerWithDefaultPrettyPrinter().writeValue(outfile, manifest);

                        } else if ("zip".equalsIgnoreCase(FilenameUtils.getExtension(f.toString()))) {
                            logger.info("Unzip apk from " + f.toString());
                            File destDir = new File(tempFolder);

                            try (ZipFile zipFile = new ZipFile(f.toString())) {
                                zipFile.stream()
                                        .filter(zipEntry -> "apk"
                                                .equalsIgnoreCase(FilenameUtils.getExtension(zipEntry.getName())))
                                        .forEach(zipEntry -> {
                                            try {
                                                File newFile = newFile(destDir, zipEntry);
                                                FileOutputStream fos = new FileOutputStream(newFile);
                                                int len;
                                                InputStream zis = zipFile.getInputStream(zipEntry);
                                                while ((len = zis.read(buffer)) > 0) {
                                                    fos.write(buffer, 0, len);
                                                }
                                                fos.close();
                                                zis.close();

                                                logger.info("Read manifest of " + newFile.toString());
                                                Map<String, Object> manifest = getAPKManifest(newFile.toString());
                                                addMetadata(manifest, f);
                                                expandIcon(manifest, newFile.toPath());

                                                ObjectMapper objectMapper = new ObjectMapper();
                                                objectMapper.writerWithDefaultPrettyPrinter().writeValue(outfile,
                                                        manifest);

                                                newFile.delete();

                                            } catch (Exception ex) {
                                                ex.printStackTrace();
                                            }
                                        });
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static Map<String, Object> getAPKManifest(String file) throws Exception {
        Runtime rt = Runtime.getRuntime();

        String[] commands = { "aapt2.exe", "dump", "badging", file };
        Process proc = rt.exec(commands);

        BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));

        Pattern linePattern = Pattern.compile("\\s*([\\w-]+):\\s?(.*)$");
        Pattern valuePattern = Pattern.compile("([\\w-]+)='([\\w.]+)'");

        Map<String, Object> res = new LinkedHashMap<>();

        String s = null;
        while ((s = stdInput.readLine()) != null) {
            Matcher line = linePattern.matcher(s);
            while (line.find()) {
                String key = line.group(1);
                res.put(key, null);

                Map<String, Object> value = new LinkedHashMap<>();
                String strValue = line.toMatchResult().group(2);
                Matcher m = valuePattern.matcher(strValue);

                boolean f = false;
                while (m.find()) {
                    f = true;
                    if (m.groupCount() > 1) {
                        value.put(m.group(1), m.group(2));
                    }
                    res.put(key, value);
                }
                if (!f) {
                    res.put(key, strValue.substring(1, strValue.length() - 1));
                }
            }
        }
        return res;
    }

    public static File newFile(File destinationDir, ZipEntry zipEntry) throws IOException {
        File destFile = new File(destinationDir, zipEntry.getName());

        String destDirPath = destinationDir.getCanonicalPath();
        String destFilePath = destFile.getCanonicalPath();

        if (!destFilePath.startsWith(destDirPath + File.separator)) {
            throw new IOException("Entry is outside of the target dir: " + zipEntry.getName());
        }

        return destFile;
    }

    @SuppressWarnings("unchecked")
    public static String getPackageNameFromMap(Map<String, Object> manifest) {
        return (String) ((Map<String, Object>) manifest.get("package")).get("name");
    }

    @SuppressWarnings("unchecked")
    public static void addMetadata(Map<String, Object> manifest, Path f) {
        //String packageName = getPackageNameFromMap(manifest);

        manifest.put("extractor", new LinkedHashMap<String, Object>());

        ((Map<String, Object>) manifest.get("extractor")).put("meta",
            Map.of(
                //"filename", FilenameUtils.getName(f.toString()),
                "timestamp", System.currentTimeMillis() / 1000L//,
                /*
                "store_url", Map.of(
                    "_","https://appstore-us.picovr.com/api/app/v1/item/info?manifest_version_code=300800000&app_language=#LANGUAGE#&device_name=A8110&package_name=" + packageName,
                    "en","https://appstore-us.picovr.com/api/app/v1/item/info?manifest_version_code=300800000&app_language=en&device_name=A8110&package_name=" + packageName,
                    "it","https://appstore-us.picovr.com/api/app/v1/item/info?manifest_version_code=300800000&app_language=it&device_name=A8110&package_name=" + packageName,
                    "es","https://appstore-us.picovr.com/api/app/v1/item/info?manifest_version_code=300800000&app_language=es&device_name=A8110&package_name=" + packageName,
                    "de","https://appstore-us.picovr.com/api/app/v1/item/info?manifest_version_code=300800000&app_language=de&device_name=A8110&package_name=" + packageName,
                    "ru","https://appstore-us.picovr.com/api/app/v1/item/info?manifest_version_code=300800000&app_language=ru&device_name=A8110&package_name=" + packageName,
                    "fr","https://appstore-us.picovr.com/api/app/v1/item/info?manifest_version_code=300800000&app_language=fr&device_name=A8110&package_name=" + packageName
                )
                */
            )
        );
    }

    @SuppressWarnings("unchecked")
    public static  Map<String, String> expandIcon(Map<String, Object> manifest, Path f) {

        Map<String, String> encodedIcons = new LinkedHashMap<>();

        manifest.keySet().stream().filter(k -> k.startsWith("application-icon")).forEach((iconKey) -> {
            Object value = manifest.get(iconKey);
            if (!(value instanceof String)) {
                return;
            }
            String iconFile = (String)value;

            if ("xml".equalsIgnoreCase(FilenameUtils.getExtension(iconFile))) {
                return;
            }

            File destDir = new File(tempFolder);
            byte[] buffer = new byte[1024];
            try (ZipFile zipFile = new ZipFile(f.toString())) {
                zipFile.stream()
                        .filter(zipEntry -> iconFile.equalsIgnoreCase(zipEntry.getName()))
                        .forEach(zipEntry -> {
                            try {
                                File newFile = new File(destDir, FilenameUtils.getName(zipEntry.getName()));
                                FileOutputStream fos = new FileOutputStream(newFile);
                                int len;
                                InputStream zis = zipFile.getInputStream(zipEntry);
                                while ((len = zis.read(buffer)) > 0) {
                                    fos.write(buffer, 0, len);
                                }
                                fos.close();
                                zis.close();

                                String encoded = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(newFile));
                                encodedIcons.put(iconKey, encoded);

                                newFile.delete();

                            } catch (Exception ex) {
                                ex.printStackTrace();
                            }
                        });
            } catch (IOException e) {
                e.printStackTrace();
            }

        });

        ((Map<String, Object>) manifest.get("extractor")).put("icons", encodedIcons);
        return encodedIcons;

    }

    public static String sha256Hex(String originalString) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(originalString.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(encodedhash);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}