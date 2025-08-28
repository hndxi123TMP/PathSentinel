package pathsent;

import soot.*;

import org.apache.commons.cli.*;
import org.apache.commons.io.FileUtils;

import pathsent.target.ManifestAnalysis;
import pathsent.target.ResourceAnalysis;
import pathsent.target.TargetedPathsAnalysis;
import pathsent.target.callgraph.AndroidCallGraphPatching;
import pathsent.target.dependency.DependencyAnalysis;
import pathsent.target.entrypoint.IEntryPointAnalysis;
import pathsent.target.entrypoint.WorkingEntryPointAnalysis;
import pathsent.target.traversal.CallGraphTraversal;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.*;
import java.util.jar.JarFile;

public class PathSentStaticAnalysis {
    public static class Configuration {
        public static final String Version = "0.2.0 - PathSentinel Edition";
        public static long StartTime = 0;
        public static final long TargetedPathTimeout = 300000; // 5 minutes
        public static long Timeout = -1;

        public static Set<String> TargetMethods = new HashSet<String>();

        public static String ApkFile = null;
        public static List<String> DynamicFiles = new ArrayList<String>();
        public static String OutputDirectory = null;
        public static String BaseOutputDirectory = null;

        public static boolean MultiThreading = false;
        public static int NumberOfThreads = 8;

        public static boolean PrintSootOutput = false;
        public static boolean PrintOutput = true;
        public static boolean PrintConstraints = false;
    }

    public static Configuration Config = new Configuration();

    public static void main(String[] args) throws Exception {
        Options options = getCommandLineOptions();

        try {
            CommandLineParser commandLineParser = new DefaultParser();
            CommandLine commands = commandLineParser.parse(options, args, true);
            parseCommandLineOptions(options, commands);
        } catch (ParseException e) {
            System.err.println(e.toString());
            printHelp(options);
            System.exit(0);
        }

        Config.StartTime = System.currentTimeMillis();
        Output.progress("Starting PathSentinel analysis for " + Config.ApkFile + " at "
                + (new Date()).toString());
        PathSentStaticAnalysis analysis = new PathSentStaticAnalysis();
        try {
            analysis.analyze();
            Output.progress("Analysis completed successfully");
        } catch (Exception e) {
            System.err.println("FATAL: Analysis failed with exception: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void analyze() throws Exception {
        System.err.println("ANALYZE: Starting analyze() method");
        // Initialize soot options in case manifest analysis requires android.R$attr class
        initializeSoot();
        System.err.println("ANALYZE: initializeSoot() completed");

        ManifestAnalysis manifestAnalysis = new ManifestAnalysis(
                PathSentStaticAnalysis.Config.ApkFile);
        ResourceAnalysis resourceAnalysis = new ResourceAnalysis(
                PathSentStaticAnalysis.Config.ApkFile);
        
        // Extract package name and set up output directory structure
        String packageName = manifestAnalysis.getPackageName();
        Config.OutputDirectory = Config.BaseOutputDirectory + "/" + packageName;
        
        // Clean output directory
        try {
            File outputDirFile = new File(Config.OutputDirectory);
            outputDirFile.mkdirs();
            FileUtils.cleanDirectory(outputDirFile);
            Output.progress("Output directory: " + Config.OutputDirectory);
        } catch (Exception e) {
            Output.error(e.toString());
            e.printStackTrace();
        }

        // Find entrypoints using comprehensive Android component discovery
        Output.progress("Searching for entrypoints");
        System.err.println("DEBUG: About to create WorkingEntryPointAnalysis");
        
        // Phase 1: Use WorkingEntryPointAnalysis while we prepare SetupApplication integration
        // Note: FlowDroid's EntryPointAnalysis has version compatibility issues with PathSentinel's older JARs
        System.err.println("PATHSENT: Using WorkingEntryPointAnalysis (Phase 1 - preparing for SetupApplication)");
        IEntryPointAnalysis finalEntryPointAnalysis = new WorkingEntryPointAnalysis(manifestAnalysis, resourceAnalysis);
        System.err.println("PATHSENT: WorkingEntryPointAnalysis found " + finalEntryPointAnalysis.getEntryPoints().size() + " entry points");
        System.err.println("DEBUG: WorkingEntryPointAnalysis completed, proceeding to ICC model generation");
        
        // Phase 2: Generate ICC model for inter-component communication analysis
        Output.progress("Generating ICC model");
        System.err.println("DEBUG: Starting ICC model generation");
        System.err.println("DEBUG: Output directory: " + PathSentStaticAnalysis.Config.OutputDirectory);
        
        String iccModelPath = PathSentStaticAnalysis.Config.OutputDirectory + "/icc_model.txt";
        System.err.println("DEBUG: ICC model will be written to: " + iccModelPath);
        
        try {
            pathsent.target.icc.IccModelGenerator iccModelGenerator = new pathsent.target.icc.IccModelGenerator(manifestAnalysis);
            System.err.println("DEBUG: IccModelGenerator created successfully");
            
            iccModelGenerator.generateIccModel();
            System.err.println("DEBUG: generateIccModel() completed");
            
            System.err.println("DEBUG: Attempting to write ICC model to file");
            iccModelGenerator.writeIccModelToFile(iccModelPath);
            System.err.println("PATHSENT: ICC model generated successfully at " + iccModelPath);
            
            // Verify file was created and report size
            java.io.File iccFile = new java.io.File(iccModelPath);
            if (iccFile.exists()) {
                System.err.println("DEBUG: ICC model file size: " + iccFile.length() + " bytes");
                try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(iccFile))) {
                    long lineCount = reader.lines().count();
                    System.err.println("DEBUG: ICC model contains " + lineCount + " lines");
                }
            } else {
                System.err.println("ERROR: ICC model file was not created!");
            }
            
        } catch (java.io.IOException e) {
            System.err.println("MAIN: Failed to write ICC model: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("ERROR: Unexpected error during ICC model generation: " + e.getMessage());
            e.printStackTrace();
        }

        // After this point, do not re-use any of the soot objects (the scene will be reset)!

        // Initialize soot options
        initializeSoot();
        
        // Mark classes from the APK as application classes (after second Soot reset)
        // In Soot 4.x, we need to explicitly mark APK classes as application classes
        for (SootClass sc : Scene.v().getClasses()) {
            if (sc.getName().startsWith("com.test.pathsent_tester")) {
                sc.setApplicationClass();
                Output.debug("SOOT: Marked as application class (after reset): " + sc.getName());
            }
        }
        
        // Debug: Print loaded target methods
        Output.debug("TARGETS: Loaded " + Config.TargetMethods.size() + " target methods:");
        for (String target : Config.TargetMethods) {
            Output.debug("  TARGET: " + target);
        }

        // Add entrypoints
        Output.progress("Setting entry points");
        Scene.v().setEntryPoints(Collections.singletonList(
                finalEntryPointAnalysis.getDummyMainMethod()));

        // Soot packs used:
        //   wjpp     - add call graph patching tags for Android-specific call edges
        //   cg.spark - create call graph and points-to analysis
        //   wjtp     - main PathSentinel analysis (path extraction and constraint generation)

        // Phase 2: Direct ICC instrumentation integration (replacing Transform approach)
        System.err.println("PATHSENT: Phase 2 - Direct ICC instrumentation integration");
        System.err.println("PATHSENT: ICC model path: " + iccModelPath);
        
        // Create IccInstrumenter directly instead of using Transform
        pathsent.target.icc.DirectIccIntegrator iccIntegrator = new pathsent.target.icc.DirectIccIntegrator(
                iccModelPath, manifestAnalysis, finalEntryPointAnalysis);
        System.err.println("PATHSENT: DirectIccIntegrator created successfully");
        
        PackManager.v().getPack("wjpp").add(new Transform("wjpp.AndroidCallGraphPatching",
                new AndroidCallGraphPatching(manifestAnalysis)));

        // EntryPointAnalysis was created before Soot reset
        
        DependencyAnalysis dependencyAnalysis = new DependencyAnalysis(resourceAnalysis,
                finalEntryPointAnalysis);
        TargetedPathsAnalysis targetedPathsAnalysis = new TargetedPathsAnalysis(
                manifestAnalysis, finalEntryPointAnalysis, dependencyAnalysis);

        CallGraphTraversal callGraphTraversal = new CallGraphTraversal(finalEntryPointAnalysis);
        callGraphTraversal.addPlugin(targetedPathsAnalysis.getCallGraphPlugin());
        dependencyAnalysis.getCallGraphPlugins().forEach(
                p -> { callGraphTraversal.addPlugin(p); });

        PackManager.v().getPack("wjtp").add(new Transform("wjtp.CallGraphTraversal",
                callGraphTraversal));

        PackManager.v().getPack("wjtp").add(new Transform("wjtp.TargetedPathsAnalysis",
                targetedPathsAnalysis));

        Output.progress("Generating call graph and points-to analysis");

        // Phase 2: Direct ICC instrumentation before call graph construction
        System.err.println("PATHSENT: Performing ICC instrumentation before call graph construction");
        iccIntegrator.instrumentBeforeCallGraphConstruction();

        // Run the wjpp pack for Android call graph patching
        System.err.println("PATHSENT: Running wjpp (whole-jimple preprocessing) pack");
        PackManager.v().getPack("wjpp").apply();
        System.err.println("PATHSENT: wjpp pack completed");

        // Run call graph construction (cg.spark)
        System.err.println("PATHSENT: Running call graph construction (cg.spark)");
        PackManager.v().getPack("cg").apply();
        System.err.println("PATHSENT: Call graph construction completed");

        // Phase 3: Multi-component ICC analysis (combining IccTA + Amandroid approaches)
        System.err.println("PATHSENT: Starting multi-component ICC analysis");
        try {
            pathsent.target.icc.MultiComponentAnalysis multiComponentAnalysis = 
                new pathsent.target.icc.MultiComponentAnalysis(manifestAnalysis, Scene.v().getCallGraph());
            
            // Create AndroidCallGraphPatching instance for multi-component analysis
            pathsent.target.callgraph.AndroidCallGraphPatching androidPatching = 
                new pathsent.target.callgraph.AndroidCallGraphPatching(manifestAnalysis);
            
            multiComponentAnalysis.performAnalysis(androidPatching);
            System.err.println("PATHSENT: Multi-component ICC analysis completed successfully");
            
        } catch (Exception e) {
            System.err.println("PATHSENT: Multi-component ICC analysis failed: " + e.getMessage());
            e.printStackTrace();
            // Continue with analysis even if multi-component analysis fails
        }

        // Phase 4: Direct ICC instrumentation after call graph construction
        System.err.println("PATHSENT: Performing ICC instrumentation after call graph construction");
        iccIntegrator.instrumentAfterCallGraphConstruction();

        // Phase 5: Call graph verification and validation
        System.err.println("PATHSENT: Verifying call graph structure and connectivity");
        try {
            pathsent.target.traversal.CallGraphVerifier callGraphVerifier = 
                new pathsent.target.traversal.CallGraphVerifier(
                    Scene.v().getCallGraph(), 
                    finalEntryPointAnalysis,
                    null  // PathSentinel uses native ICC, not IccCallGraphEnhancer
                );
            
            callGraphVerifier.verifyCallGraph();
            System.err.println("PATHSENT: Call graph verification completed");
            
        } catch (Exception e) {
            System.err.println("PATHSENT: Call graph verification failed: " + e.getMessage());
            e.printStackTrace();
            // Continue with analysis even if verification fails
        }

        // Run the remaining packs (wjtp)
        System.err.println("PATHSENT: Running wjtp (whole-jimple transformation) pack");
        PackManager.v().getPack("wjtp").apply();
        System.err.println("PATHSENT: wjtp pack completed");
    }

    public static void initializeSoot() {
        soot.G.reset();

        // Source format: APK
        soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
        // Output format: None
        soot.options.Options.v().set_output_format(
                soot.options.Options.output_format_none);

        soot.options.Options.v().set_process_multiple_dex(true);
        soot.options.Options.v().set_soot_classpath("./libs/rt.jar");
        soot.options.Options.v().set_android_jars("/home/eddy/Research/android-platforms");
        soot.options.Options.v().set_prepend_classpath(true);
        soot.options.Options.v().set_allow_phantom_refs(true);
        soot.options.Options.v().set_force_overwrite(true);
        soot.options.Options.v().set_whole_program(true);
        soot.options.Options.v().setPhaseOption("cg", "callgraph-tags:true");
        soot.options.Options.v().setPhaseOption("cg.spark", "on");
        soot.options.Options.v().setPhaseOption("cg.spark", "string-constants:true");

        // Suppress output (temporarily disabled for ICC debugging)
        // if (!Config.PrintSootOutput) {
        //     try {
        //         G.v().out = new PrintStream(new File("/dev/null"));
        //     } catch (Exception e) {
        //         e.printStackTrace();
        //     }
        // }

        //soot.options.Options.v().setPhaseOption("cg", "verbose:true");

        // Exclude certain packages for better performance
        List<String> excludeList = new LinkedList<String>();
        excludeList.add("java.");
        excludeList.add("sun.misc.");
        excludeList.add("android.");
        excludeList.add("com.android.");
        excludeList.add("dalvik.system.");
        excludeList.add("org.apache.");
        excludeList.add("soot.");
        excludeList.add("javax.servlet.");
        soot.options.Options.v().set_exclude(excludeList);
        soot.options.Options.v().set_no_bodies_for_excluded(true);

        // Add code to be analyzed
        List<String> inputCode = new ArrayList<String>();
        inputCode.add(Config.ApkFile);

        soot.options.Options.v().set_process_dir(inputCode);

        Scene.v().loadNecessaryClasses();
        
        // Mark classes from the APK as application classes  
        // In Soot 4.x, we need to explicitly mark APK classes as application classes
        for (SootClass sc : Scene.v().getClasses()) {
            if (sc.getName().startsWith("com.test.pathsent_tester")) {
                sc.setApplicationClass();
                Output.debug("SOOT: Marked as application class: " + sc.getName());
            }
        }
    }

    private static Options getCommandLineOptions() {
        Options options = new Options();
        options.addOption(Option.builder("o").longOpt("output")
                .required(false).hasArg(true).argName("dir")
                .desc("Output directory for extracted paths and constraints "
                        + "(default: \"./pathSentOutput\")")
                .build()
        );
        options.addOption(Option.builder("j").longOpt("multithreading")
                .required(false).hasArg(true).argName("threads")
                .desc("Enable multi-threaded analysis and set the number of threads")
                .build()
        );
        options.addOption(Option.builder("k").longOpt("timeout")
                .required(false).hasArg(true).argName("minutes")
                .desc("Time limit for analysis (best effort)")
                .build()
        );
        options.addOption(Option.builder("x").longOpt("nostdout")
                .required(false).hasArg(false)
                .desc("Do not print extracted paths in standard output")
                .build()
        );
        options.addOption(Option.builder("y").longOpt("constraints")
                .required(false).hasArg(false)
                .desc("Print extracted constraints in standard output")
                .build()
        );
        options.addOption(Option.builder("z").longOpt("sootOutput")
                .required(false).hasArg(false)
                .desc("Print output from Soot framework and FlowDroid entry-point extraction")
                .build()
        );
        options.addOption(Option.builder("h").longOpt("help")
                    .required(false).hasArg(false)
                    .desc("Print help")
                    .build()
        );
        options.addOption(Option.builder("v").longOpt("version")
                .required(false).hasArg(false)
                .desc("Print version")
                .build()
        );

        OptionGroup targetOptions = new OptionGroup();
        targetOptions.addOption(Option.builder("t").longOpt("targets")
                .required(false).hasArg(true).argName("file")
                .desc("Input file listing target methods for analysis "
                        + "(default: \"./targetedMethods.txt\")")
                .build()
        );

        options.addOptionGroup(targetOptions);
        return options;
    }

    private static void parseCommandLineOptions(Options options, CommandLine commands)
            throws Exception {
        if (commands.hasOption("h")) {
            printHelp(options);
            System.exit(0);
        }

        if (commands.hasOption("v")) {
            System.out.println("PathSentinel version: " + Config.Version);
            System.exit(0);
        }

        List<String> operands = commands.getArgList();
        if (operands.size() != 1) {
            throw new ParseException("Missing APK file", 0);
        }

        Config.ApkFile = operands.get(0);
        // Store the base output directory - will append package name later
        Config.BaseOutputDirectory = commands.getOptionValue("o", "./pathSentOutput");

        if (commands.hasOption("j")) {
            Config.MultiThreading = true;

            try {
                Config.NumberOfThreads = Integer.parseInt(commands.getOptionValue("j"));
            } catch (Exception e) {
                System.err.println("Cannot parse multi-threading parameter");
                System.err.println("Exception: " + e.toString());
                System.exit(1);
            }

            if (Config.NumberOfThreads <= 1) {
                System.err.println("Warning: ignoring multi-threading parameter ("
                        + Config.NumberOfThreads + ")");
                Config.MultiThreading = false;
            }
        }

        if (commands.hasOption("k")) {
            try {
                Config.Timeout = 60000 * Integer.parseInt(commands.getOptionValue("k"));
            } catch (Exception e) {
                System.err.println("Cannot parse timeout parameter");
                System.err.println("Exception: " + e.toString());
                System.exit(1);
            }
        }

        if (commands.hasOption("x")) {
            Config.PrintOutput = false;
        }

        if (commands.hasOption("y")) {
            Config.PrintConstraints = true;
        }

        if (commands.hasOption("z")) {
            Config.PrintSootOutput = true;
        }

        String targetMethodsFile = commands.getOptionValue("t", "./targetedMethods.txt");
        //Output.log("Target: " + targetMethodsFile);

        try {
            BufferedReader br = new BufferedReader(new FileReader(targetMethodsFile));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                //String methodSignature = line.substring(line.indexOf("<") + 1,
                //    line.lastIndexOf(">"));
                String methodSignature = line;
                Config.TargetMethods.add(methodSignature);
            }

            br.close();

        } catch (Exception e) {
            System.err.println("Cannot read target methods file");
            System.err.println("Exception: " + e.toString());
            System.exit(1);
        }
    }

    private static void printHelp(Options options) {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp("PathSentinel [options] <APK>",
                "PathSentinel: Advanced static analysis for Android ICC vulnerability detection",
                options, "", false);
    }
}

