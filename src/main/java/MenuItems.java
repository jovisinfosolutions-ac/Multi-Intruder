import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.swing.SwingUtils;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.basic.BasicButtonUI;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.text.BadLocationException;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.List;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MenuItems implements ContextMenuItemsProvider, ExtensionUnloadingHandler {

    private final MontoyaApi api;
    private Logging logger;

    private HttpRequestEditor requestEditor;


    private final Map<Integer, Position> positions = new ConcurrentHashMap<>();
    private final Map<Integer, String> wordList = new ConcurrentSkipListMap<>();
    private final Map<Integer, HttpRequest> req = new ConcurrentHashMap<>();
    private final Map<Integer, Boolean> selected = new ConcurrentHashMap<>();
    private final Map<Integer, Boolean> fullSelected = new ConcurrentHashMap<>();
    private final Map<Integer, JButton> buttons = new ConcurrentHashMap<>();
    private final List<AttackSession> sessions = Collections.synchronizedList(new ArrayList<>());


    private int num = 1;
    private int find;
    private int activeId = -1;
    private int wordNum = 1;
    private int attackNum = 0;


    private boolean added = false;
    private boolean loaded = false;
    private boolean pasted = false;
    private boolean stateSelected = false;


    private final JPanel panel = new JPanel(new BorderLayout());
    private final JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

    private final JCheckBox url_encode = new JCheckBox("URL Encode", true);

    private JTable wordTable;
    private JPanel leftAllContainer = new JPanel(new BorderLayout());
    private JPanel rightContainer = new JPanel(new BorderLayout());
    private JPanel leftPanel = new JPanel();
    private JTextField rateField;
    private JTextField url_value;
    private DefaultTableModel wordTableModel;
    private JCheckBox checkBox;
    private JCheckBox checkBoxFullPath;
    JScrollPane rightScrollPane = new JScrollPane(rightContainer);


    public MenuItems(MontoyaApi api) {
        this.api = api;
        this.logger = api.logging();
        createUI();
        api.extension().registerUnloadingHandler(this);
    }

    //UI logic
    private void createUI() {
        rightPanel();
        leftPanel();
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,leftAllContainer,rightScrollPane);
        splitPane.setResizeWeight(0.0);
        splitPane.setContinuousLayout(true);
        splitPane.setDividerSize(5);
        splitPane.setDividerLocation(900);
        panel.add(splitPane,BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Multi-Intruder",panel);

    }

    //run button
    private void run() {
        JButton run = new JButton("Run");
        run.setPreferredSize(new Dimension(100,30));
        topPanel.add(run);
        panel.add(topPanel,BorderLayout.NORTH);


        //when run button clicked
        run.addActionListener(e -> {

            if(!added) return;
            if (!loaded && !pasted) return;
            if(wordList.isEmpty()) return;

            AtomicInteger runNum = new AtomicInteger(0);

            //new Session created for attack when run clicked
            AttackSession session = new AttackSession();

            //30 scheduler and 10 executor threads created for each session
            session.scheduler = Executors.newScheduledThreadPool(30);
            session.executor =  Executors.newFixedThreadPool(10);
            attackNum++;
            session.urlEncode = url_encode.isSelected();
            session.url_value = url_value.getText();

            //session added in ArrayList
            sessions.add(session);

            //rate
            try{
                String text = rateField.getText().trim();

                if(text.isEmpty()) {
                    session.rate = 1000;
                }else {
                    int requestPerSecond = Integer.parseInt(text);
                    if(requestPerSecond <= 0) {
                        session.rate = 1000;
                    }else {
                        session.rate = Math.max(1, 1000/requestPerSecond);
                    }
                }

            }catch (NumberFormatException ex){
                session.rate = 1000;
                logger.logToError("Invalid delay using 1000 ms");
            }


            session.running.set(true);

            //result table called
            createResultTable(session);
            session.scheduler.execute(() -> runSchedule(session));
            frame(session);
            runNum.set(0);
        });

    }

    //runSchedule called from run()
    private void runSchedule(AttackSession session) {

        for(Integer id : req.keySet()) {
            session.executor.submit(() -> attack(id, session));
        }
    }

    //attack called from runSchedule
    private void attack(int id, AttackSession session) {

        Position pos = positions.get(id);
        if(pos == null) return;
        int start = pos.start;
        int end = pos.end;

        //iterate through wordLists
        if(wordList.isEmpty()) return;

        int delay = 0;

        for(Map.Entry<Integer, String> words : wordList.entrySet()) {

            String list = words.getValue();
            int currentDelay = delay;
            int requestId = session.runNum.incrementAndGet();
            session.tasks.incrementAndGet();
            session.scheduler.schedule(() -> {

                synchronized (session.lock) {
                    while (session.pause) {
                        try{
                            session.lock.wait();
                        }catch(InterruptedException e){
                            Thread.currentThread().interrupt();
                            StringWriter sw = new StringWriter();
                            e.printStackTrace(new PrintWriter(sw));
                            logger.logToError(sw.toString());
                            return;
                        }
                    }
                }

                try{
                    HttpRequest reqString = req.get(id);
                    if(reqString == null) return ;
                    String url = removeMakers(reqString.toString());

                    String payload =  list;

                    //url encoding for payload
                    if(session.urlEncode) {
                        payload = encodePayload(payload, session.url_value);
                    }

                    StringBuilder sb = new StringBuilder(url);
                    sb.replace(start, end, payload);
                    String text = sb.toString();

                    HttpRequest httpRequest = HttpRequest.httpRequest(reqString.httpService(), text);

                    HttpRequestResponse response = api.http().sendRequest(httpRequest);

                    var responseObj = response.response();
                    if(responseObj == null) return;

                    short status = response.response().statusCode();
                    String reqURL = response.request().url();
                    String location = "";
                    int length = response.response().toString().length();

                    if(status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                        location = response.response().headerValue("Location");

                        if(location == null) location = "";
                    }

                    String finalLocation = location;

                    Result result = new Result(requestId, reqURL, status, length, finalLocation) ;

                    session.results.put(requestId, result);

                    //result to table
                    SwingUtilities.invokeLater(() -> session.tableModel.addRow(new Object[]{requestId,id, reqURL, status, length, finalLocation}));
                }catch (Exception e){
                    StringWriter sw = new StringWriter();
                    e.printStackTrace(new PrintWriter(sw));
                    logger.logToError(sw.toString());
                }
                finally {
                    int remain = session.tasks.decrementAndGet();
                    if(remain == 0) session.running.set(false);
                }
            }, currentDelay, TimeUnit.MILLISECONDS);
            delay += session.rate;

        }
    }

    //url encoding
    private String encodePayload(String path, String value) {
        StringBuilder sb = new StringBuilder();

        if(value == null || value.isEmpty()) return path;

        for(char ch : path.toCharArray()) {
            if(value.indexOf(ch) >= 0) {
                sb.append(String.format("%%%02X", (int)ch));
            }else{
                sb.append(ch);
            }
        }

        return sb.toString();
    }


    //result table
    private void createResultTable(AttackSession session) {

        session.frame = new JFrame("Attack Results "+ attackNum);
        session.frame.setLayout(new BorderLayout());
        session.frame.setFont(new Font("Consolas", Font.PLAIN, 12));

        JPanel exportPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton filter = new JButton("Filter");
        JButton export = new JButton("Export");
        JButton pauseButton = new JButton("Pause");

        pauseButton.setMaximumSize(new Dimension(120,30));
        export.setMaximumSize(new Dimension(120,30));

        exportPanel.add(filter);
        exportPanel.add(pauseButton);
        exportPanel.add(export);

        session.frame.add(exportPanel,BorderLayout.NORTH);

        String[] column = {"Request No","Id", "URL", "Status Code", "Length", "RedirectURL"};
        session.tableModel = new DefaultTableModel(column, 0){
            @Override
            public boolean isCellEditable(int row, int column) {return false;}

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                switch (columnIndex) {
                    case 0:
                    case 1:
                    case 3:
                    case 4:
                        return Integer.class;
                    default:
                        return String.class;
                }
            }

        };

        //table
        JTable table = new JTable(session.tableModel);
        table.setAutoCreateRowSorter(true);
        table.setRowSelectionAllowed(true);
        table.setCellSelectionEnabled(true);
        table.getColumnModel().getColumn(2).setPreferredWidth(400);
        table.getColumnModel().getColumn(5).setPreferredWidth(400);
        JScrollPane tableScroll = new JScrollPane(table);
        session.frame.add(tableScroll, BorderLayout.CENTER);
        session.frame.setSize(new Dimension(900,600));
        session.frame.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        session.frame.setVisible(true);

        //sorter
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(session.tableModel);
        table.setRowSorter(sorter);

        //copy URL
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyUrl = new JMenuItem("copy URL");
        popupMenu.add(copyUrl);

        copyUrl.addActionListener(e -> {
            int copyRow = table.getSelectedRow();
            int copyColumn = table.getSelectedColumn();
            if(copyRow == -1) return;
            int modelRow = table.convertRowIndexToModel(copyRow);
            int modelColumn = table.convertColumnIndexToModel(copyColumn);
            String url = session.tableModel.getValueAt(modelRow, modelColumn).toString();
            StringSelection select = new StringSelection(url);

            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(select, null);
        });

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                showPopup(e);
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                showPopup(e);
            }

            private void showPopup(MouseEvent e) {
                if(!e.isPopupTrigger()) return;

                int row = table.rowAtPoint(e.getPoint());
                if(row >= 0) {
                    table.setRowSelectionInterval(row, row);
                }

                popupMenu.show(e.getComponent(),e.getX(),e.getY());
            }
        });



        //filter
        filter.addActionListener(e -> {

            if(session.filterFrame == null) {
                createFilterFrame(session, sorter);

            }

            session.filterFrame.setVisible(true);

        });


        //pause logic
        pauseButton.addActionListener(e -> {
            session.pause = !session.pause;

            if(session.pause) {
                session.pause = true;
                pauseButton.setText("Resume");
            }else {
                synchronized (session.lock) {
                    session.pause = false;
                    session.lock.notifyAll();
                }
                pauseButton.setText("Pause");
            }
        });

        //export logic
        export.addActionListener(e -> exportLogs(session));

    }

    private void createFilterFrame(AttackSession session, TableRowSorter<?> sorter) {

        session.filterFrame = new JFrame("Apply Filter");
        session.filterFrame.setLayout(new BorderLayout());

        session.success = new JCheckBox("2xx [success]", true);
        session.redirection = new JCheckBox("3xx [redirection]", true);
        session.requestError = new JCheckBox("4xx [request error]", true);
        session.serverError = new JCheckBox("5xx [server error]", true);

        JPanel filterbox = new JPanel();
        filterbox.setLayout(new BoxLayout(filterbox, BoxLayout.Y_AXIS));

        //button
        JButton applyFilter = new JButton("Apply");

        JPanel filterBottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        Color normal = new Color(220, 90, 0);
        Color hover = new Color(170, 90, 0);
        applyFilter.setForeground(Color.WHITE);
        applyFilter.setBackground(normal);

        applyFilter.setUI(new BasicButtonUI());
        applyFilter.setOpaque(true);
        applyFilter.setContentAreaFilled(true);
        applyFilter.setBorderPainted(false);



        applyFilter.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                applyFilter.setBackground(hover);
            }
            @Override
            public void mouseExited(MouseEvent e) {
                applyFilter.setBackground(normal);
            }
            @Override
            public void mousePressed(MouseEvent e) {
                apply(session, sorter);
                session.filterFrame.setVisible(false);
            }
        });


        filterBottom.add(applyFilter);

        filterbox.add(session.success);
        filterbox.add(session.redirection);
        filterbox.add(session.requestError);
        filterbox.add(session.serverError);
        session.filterFrame.add(filterbox, BorderLayout.CENTER);
        session.filterFrame.add(filterBottom, BorderLayout.SOUTH);

        session.filterFrame.setSize(new Dimension(300,200));
        session.filterFrame.setLocationRelativeTo(session.frame);
    }

    private void apply(AttackSession session, TableRowSorter<?> sorter) {

        List<RowFilter<Object, Object>> filters = new ArrayList<>();

        if(session.success.isSelected()) {
            filters.add(RowFilter.regexFilter("^2\\d\\d$", 3));
        }
        if(session.redirection.isSelected()) {
            filters.add(RowFilter.regexFilter("^3\\d\\d$", 3));
        }
        if(session.requestError.isSelected()) {
            filters.add(RowFilter.regexFilter("^4\\d\\d$", 3));
        }
        if(session.serverError.isSelected()) {
            filters.add(RowFilter.regexFilter("^5\\d\\d$", 3));
        }
        if(filters.isEmpty()) {
            sorter.setRowFilter(null);
        }
        else {
            sorter.setRowFilter(RowFilter.orFilter(filters));
        }
        session.filterFrame.setVisible(false);
    }

    private void frame(AttackSession session) {
        //frame is closed
        session.frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        session.frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                session.running.set(false);

                if(sessions.isEmpty()) {
                    sessions.remove(session);
                }

                if(session.filterFrame != null) {
                    session.filterFrame.dispose();
                }

                synchronized (session.lock) {
                    session.pause = false;
                    session.lock.notifyAll();
                }
                session.scheduler.shutdownNow();
                session.executor.shutdownNow();
//                logger.logToOutput("Attack stopped");
            }
        });

    }

    private void exportLogs(AttackSession session) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("export.csv"));
        int userSelection = fileChooser.showSaveDialog(null);

        if(userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            try {
                List<String> lines = new ArrayList<>();

                for(Result result : session.results.values()) {
                    int id = result.getRequestId();

                    lines.add(String.format("%-6d, %-100s, %-5d, %5d, %-100s",id, result.getUrl(), result.getStatusCode(),result.getResponseLength(), result.getRedirectURL()));
                }

                Files.write(fileToSave.toPath(), lines, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            } catch (IOException e) {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                logger.logToError(sw.toString());
            }
        }
    }

    //add Button
    private void addButton() {

        JButton addButton = new JButton("Add §");
        addButton.setPreferredSize(new Dimension(100,30));
        topPanel.add(addButton);
        panel.add(topPanel, BorderLayout.NORTH);
        addButton.addActionListener(e -> {

            //get request from editor
            HttpRequest current = requestEditor.getRequest();
            if(current == null) return;

            if(requestEditor.selection().isPresent()) {
                var selection = requestEditor.selection().get();

                int start = selection.offsets().startIndexInclusive();
                int end = selection.offsets().endIndexExclusive();

                String original = removeMakers(current.toString());
                positions.put(find,new Position(start, end));

                HttpService httpService = current.httpService();
                HttpRequest newRequest = HttpRequest.httpRequest(httpService, original);
                req.put(find, newRequest);

                renderRequest(original);
                added = true;
            }
            else{
                int start = requestEditor.caretPosition();
                int end = requestEditor.caretPosition();

                String original = removeMakers(current.toString());
                positions.put(find,new Position(start, end));

                HttpService httpService = current.httpService();
                HttpRequest newRequest = HttpRequest.httpRequest(httpService, original);
                req.put(find, newRequest);

                renderRequest(original);
                added = true;
            }

            if(checkBoxFullPath.isSelected() && added) {
                checkBoxFullPath.setSelected(false);
                fullSelected.put(find, false);
            }

        });
    }

    //add Pattern to the request
    private void renderRequest(String original) {
        StringBuilder sb = stringBuilder(original, find);

        try {

            HttpRequest url = req.get(find);
            HttpService httpService = url.httpService();
            HttpRequest newRequest = HttpRequest.httpRequest(httpService, sb.toString());

            requestEditor.setRequest(newRequest);

        }catch (Exception e){
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            logger.logToError(sw.toString());
        }

    }

    //add marker to request string
    private StringBuilder stringBuilder(String original, int find) {
        StringBuilder sb = new StringBuilder(original);

        int  start = positions.get(find).start;
        int  end = positions.get(find).end;
        if (start == end) {
            sb.insert(start, "§§");
        } else {
            sb.insert(end, "§");
            sb.insert(start, "§");
        }
        added = true;
        loaded = true;
        return sb;
    }

    //remove pattern from the text or Strings
    private String removeMakers(String text) {
        return text.replace("§","");
    }

    //remove pattern from the request
    private void clearButton() {
        JButton clearButton = new JButton("clear §");
        clearButton.setPreferredSize(new Dimension(100,30));
        topPanel.add(clearButton);
        panel.add(topPanel,BorderLayout.NORTH);

        //clear the pattern from words
        clearButton.addActionListener(e -> {
            selected.remove(find);


            positions.remove(find);
            added = false;

            checkBox.setSelected(false);
            checkBoxFullPath.setSelected(false);
            fullSelected.remove(find);

            HttpRequest url = req.get(find);

            requestEditor.setRequest(url);

        });
    }

    //checkbox to add full path to request
    private void checkBox() {
        checkBox = new JCheckBox("BruteForce full path for this request");
        topPanel.add(checkBox);
        panel.add(topPanel,BorderLayout.NORTH);

        checkBox.addActionListener( e -> {
            if(req.isEmpty()) {
                checkBox.setSelected(false);
                return;
            }

            boolean state = checkBox.isSelected();
            selected.put(find, state);
            if (state) {
                if (checkBox.isSelected()) {
                    fullSelected.remove(find);

                    Boolean fullState = fullSelected.get(find);
                    checkBoxFullPath.setSelected(fullState != null && fullState);

                    HttpRequest singleRequest = req.get(find);
                    String current = removeMakers(singleRequest.toString());

                    String path = singleRequest.path();

                    int start = current.indexOf(path)+1;
                    int end = start + path.length()-1;

                    positions.put(find, new Position(start, end));
                    renderRequest(current);

                }
            } else {
                String text = requestEditor.getRequest().toString();
                String original = removeMakers(text);

                HttpRequest url = req.get(find);
                HttpService httpService = url.httpService();
                HttpRequest newRequest = HttpRequest.httpRequest(httpService, original);
                req.put(find,newRequest);
                positions.remove(find);

                requestEditor.setRequest(newRequest);

            }
        });
    }

    //Add all request path
    private void checkBoxFullPath() {
        checkBoxFullPath = new JCheckBox("BruteForce full path for all request");
        topPanel.add(checkBoxFullPath);
        panel.add(topPanel, BorderLayout.NORTH);

        checkBoxFullPath.addActionListener(e -> {
            if(req.isEmpty()) {
                checkBoxFullPath.setSelected(false);
                fullSelected.clear();
                return;
            }
            stateSelected = checkBoxFullPath.isSelected();
            if(stateSelected){

                checkBox.setSelected(false);
                selected.clear();

                for (Map.Entry<Integer, HttpRequest> allRequest : req.entrySet()) {
                    HttpRequest singleRequest = allRequest.getValue();
                    String text = removeMakers(allRequest.getValue().toString());
                    int id = allRequest.getKey();

                    String path = singleRequest.path();

                    int start = text.indexOf(path)+1;
                    int end = start + path.length()-1;

                    String original = removeMakers(text);
                    positions.put(id, new Position(start, end));
                    fullSelected.put(id, true);
                    renderRequestForAll(id, original,singleRequest);
                }
            }else{
               fullSelected.clear();
                positions.clear();
                displayReq();
                checkBox.setSelected(false);

            }
        });
    }

    //display request
    private void displayReq() {

        HttpRequest text = req.get(find);
        requestEditor.setRequest(text);
    }

    //add markers to all request
    private void renderRequestForAll(int id, String original,HttpRequest singleRequest) {
        StringBuilder sb = stringBuilder(original, id);
        try {
            HttpService httpService = singleRequest.httpService();
            HttpRequest newRequest = HttpRequest.httpRequest(httpService, sb.toString());

            requestEditor.setRequest(newRequest);

        }catch (Exception e){
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            logger.logToError(sw.toString());
        }
    }

    // request editor
    private void requestEditor() {
        requestEditor = api.userInterface().createHttpRequestEditor();

        JScrollPane requestScroll = new JScrollPane(requestEditor.uiComponent());
        requestScroll.setPreferredSize(new Dimension(500, 200));
        leftAllContainer.setPreferredSize(new Dimension(500,400));
        leftAllContainer.add(requestEditor.uiComponent(),BorderLayout.CENTER);

    }

    //right Panel
    private void rightPanel(){

        rightContainer.setPreferredSize(new Dimension(500,400));
        rightContainer.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY, 1,true));

        Dimension buttonSize = new Dimension(120,30);

        JPanel rightTopPanel = new JPanel();
        rightTopPanel.setLayout(new BoxLayout(rightTopPanel,BoxLayout.Y_AXIS));
        rightTopPanel.setBorder(BorderFactory.createEmptyBorder(10,10,10,0));

        //LoadButton
        JLabel load = new JLabel("Load WordLists:");
        JButton loadButton = new JButton("Load");
        JButton pasteButton = new JButton("Paste");
        loadButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        pasteButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        loadButton.setMaximumSize(buttonSize);
        pasteButton.setMaximumSize(buttonSize);

        rightTopPanel.add(load);
        rightTopPanel.add(Box.createVerticalStrut(5));
        rightTopPanel.add(loadButton);
        rightTopPanel.add(Box.createVerticalStrut(5));
        rightTopPanel.add(pasteButton);
        rightTopPanel.add(Box.createVerticalStrut(5));

        //word TextArea
        String[] column = {"No","wordsLists"};
        wordTableModel = new DefaultTableModel(column, 0){@Override public boolean isCellEditable(int row, int column) {return false;}};
        wordTable = new JTable(wordTableModel);
        wordTable.getColumnModel().getColumn(0).setMinWidth(0);
        wordTable.getColumnModel().getColumn(0).setMaxWidth(0);
        wordTable.getColumnModel().getColumn(0).setWidth(0);
        wordTable.setAutoCreateRowSorter(false);
        wordTable.setRowSelectionAllowed(true);
        wordTable.setCellSelectionEnabled(true);
        wordTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        wordTable.getTableHeader().setReorderingAllowed(false);

        wordTable.setRowHeight(25);
        wordTable.getColumnModel().getColumn(1).setPreferredWidth(400);

        JScrollPane wordScroll = new JScrollPane(wordTable);
        wordScroll.setMaximumSize(new Dimension(400, 100));
        rightContainer.add(wordScroll,BorderLayout.CENTER);

        loadButton.addActionListener(e -> {if(added && loaded) load();});
        
        pasteButton.addActionListener(e -> {if(added) paste();});

        JButton addPayload = new JButton("Add");
        JTextField addWordText = new PlaceholderTextField("Enter a new item");
        JButton removePayload = new JButton("Remove");
        JButton clearPayload = new JButton("clear");
        addPayload.setAlignmentX(Component.LEFT_ALIGNMENT);
        removePayload.setAlignmentX(Component.LEFT_ALIGNMENT);
        clearPayload.setAlignmentX(Component.LEFT_ALIGNMENT);
        addWordText.setAlignmentX(Component.LEFT_ALIGNMENT);
        addPayload.setMaximumSize(buttonSize);
        removePayload.setMaximumSize(buttonSize);
        clearPayload.setMaximumSize(buttonSize);
        addWordText.setMaximumSize(new Dimension(250,30));

        rightTopPanel.add(addPayload);
        rightTopPanel.add(Box.createVerticalStrut(5));
        rightTopPanel.add(addWordText);
        rightTopPanel.add(Box.createVerticalStrut(5));
        rightTopPanel.add(removePayload);
        rightTopPanel.add(Box.createVerticalStrut(5));
        rightTopPanel.add(clearPayload);
        rightTopPanel.add(Box.createVerticalStrut(25));

        JLabel rateLabel = new JLabel("Request/s:");
        rateField = new PlaceholderTextField("1");
        rateField.setMaximumSize(new Dimension(100,30));
        rateField.setAlignmentX(Component.LEFT_ALIGNMENT);

        url_value = new JTextField(" ./\\=<>?+&*;:\"{}|^`#");
        url_value.setAlignmentX(Component.LEFT_ALIGNMENT);
        url_value.setMaximumSize(new Dimension(250,30));

        rightTopPanel.add(rateLabel);
        rightTopPanel.add(Box.createVerticalStrut(5));
        rightTopPanel.add(rateField);
        rightTopPanel.add(Box.createVerticalStrut(15));
        rightTopPanel.add(url_encode);
        rightTopPanel.add(Box.createVerticalStrut(5));
        rightTopPanel.add(url_value);

        rightTopPanel.setPreferredSize(new Dimension(160,500));
        rightContainer.add(rightTopPanel,BorderLayout.WEST);

        //add
        addPayload.addActionListener(e -> {
            if(!added) return;
            String text = addWordText.getText();
            if(text.isEmpty()) return;
            int id =wordNum++;
            displayWords(id,text);
            addWordText.setText("");
            addWordText.requestFocusInWindow();
        });

        //enter item field
        addWordText.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {

                    if (!added) return;

                    String text = addWordText.getText().trim();

                    if (text.isEmpty()) return;

                    int id = wordNum++;
                    displayWords(id, text);

                    addWordText.setText("");
                    addWordText.requestFocusInWindow();
                }
            }
        });

        //clear
        clearPayload.addActionListener(e -> {
            addWordText.setText("");
            wordList.clear();
            wordTableModel.setRowCount(0);
            wordNum = 1;
            pasted = false;
        });

        //remove
        removePayload.addActionListener(e -> {
            int[] rows = wordTable.getSelectedRows();
            if(rows.length == 0) return;

            for(int i = rows.length-1; i >= 0; i--) {
                int viewRow = rows[i];
                int modelRow = wordTable.convertRowIndexToModel(viewRow);
                int id = (int) wordTableModel.getValueAt(modelRow,0);
                wordList.remove(id);
                wordTableModel.removeRow(modelRow);
            }
        });

    }

    //load wordList from system
    private void load() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(panel);

        if(result == JFileChooser.APPROVE_OPTION){

            File selectedFile = fileChooser.getSelectedFile();
            try(BufferedReader reader = new BufferedReader(new FileReader(selectedFile))){

                wordList.clear();
                wordTableModel.setRowCount(0);

                String line;
                while((line = reader.readLine()) != null) {
                    int id =wordNum++;
                    line = line.trim();
                    displayWords(id,line);
                }
                loaded = true;
            } catch (IOException e) {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                logger.logToError(sw.toString());
            }
        }
    }

    //display words in wordlist Area
    private void displayWords(int id, String line) {
        wordList.put(id,line.trim());
        SwingUtilities.invokeLater(() -> wordTableModel.addRow(new Object[]{id, line}));
    }


    //paste wordlist from clipboard
    private void paste() {
        try{
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            String text = (String)clipboard.getData(DataFlavor.stringFlavor);
            if(text == null || text.isEmpty()) return;

            String[] lines = text.split("\\R");

            for(String line : lines) {
                line = line.trim();
                if(!line.isEmpty()){
                    int id =wordNum++;
                    displayWords(id,line);
                }
            }
            pasted = true;
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            logger.logToError(sw.toString());
        }
    }

    //left panel
    private void leftPanel() {

        addButton();
        clearButton();
        run();
        checkBox();
        checkBoxFullPath();
        requestEditor();

        JPanel leftContainer = new JPanel(new BorderLayout());
        leftPanel.setLayout(new BoxLayout(leftPanel,BoxLayout.Y_AXIS));
        leftPanel.setBorder(BorderFactory.createEmptyBorder(10,0,0,0));
        JScrollPane leftScroll = new JScrollPane(leftPanel);
        leftScroll.setPreferredSize(new Dimension(120,200));
        leftContainer.add(leftScroll, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT,5,10));
        bottomPanel.setPreferredSize(new Dimension(150,100));

        //delete button
        JButton delete = new JButton("Delete");
        delete.setAlignmentX(Component.CENTER_ALIGNMENT);
        delete.setPreferredSize(new Dimension(120,35));
        bottomPanel.add(delete);

        //delete all button
        JButton deleteAll = new JButton("Delete-All");
        deleteAll.setAlignmentX(Component.CENTER_ALIGNMENT);
        deleteAll.setPreferredSize(new Dimension(120,35));
        bottomPanel.add(deleteAll);
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(0,10,0,0));
//        bottomPanel.add(Box.createVerticalStrut(5));

        leftContainer.add(bottomPanel,BorderLayout.SOUTH);
        leftAllContainer.add(leftContainer,BorderLayout.WEST);

        //delete key clicked
        delete.addActionListener(e -> {
            req.remove(find);
            positions.remove(find);
            selected.remove(find);
            fullSelected.remove(find);

            if( req.isEmpty()) {
                wordTableModel.setRowCount(0);
                url_value.setText(" ./\\=<>?+&*;:\"{}|^`#");
            }

            HttpRequest emptyRequest = HttpRequest.httpRequest("");
            requestEditor.setRequest(emptyRequest);

            deleteButton();
        });

        //delete all key clicked
        deleteAll.addActionListener(e -> {
            req.clear();
            positions.clear();
            selected.clear();
            fullSelected.clear();

            HttpRequest emptyRequest = HttpRequest.httpRequest("");
            requestEditor.setRequest(emptyRequest);

            deleteAllButton();
            loaded = false;
            wordTableModel.setRowCount(0);
            url_value.setText(" ./\\=<>?+&*;:\"{}|^`#");
            wordList.clear();
            rateField.setText("");
            attackNum = 0;
            num = 1;
        });

    }

    //delete all action called
    private void deleteAllButton() {

        leftPanel.removeAll();
        leftPanel.revalidate();
        leftPanel.repaint();
        deleteAll();
    }

    //delete action called
    private void deleteButton() {
        JButton button = buttons.remove(find);

        if(button != null) {
            leftPanel.remove(button);
            leftPanel.revalidate();
            leftPanel.repaint();
        }
        deleteAll();
    }

    //common parameters to delete in both delete button
    private void deleteAll() {

        checkBox.setSelected(false);
        checkBoxFullPath.setSelected(false);

    }



    //provide right click option to extension in the request Tab
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {

        JMenuItem item = new JMenuItem("Multi-Intruder");

        item.addActionListener(e-> {
            HttpRequest request = null;

            //Repeater / Editor Tabs
            var editor = event.messageEditorRequestResponse();
            if(editor.isPresent() && editor.get().requestResponse() != null) {
                request = editor.get().requestResponse().request();
            }

            //Proxy /Logger
            if(request == null) {
                request = event.selectedRequestResponses().stream().findFirst().map(HttpRequestResponse::request).orElse(null);
            }

            if(request == null) return ;

            requestEditor.setRequest(request);
            find = num;
            req.put(num , request);
            fullSelected.putIfAbsent(find, false);

            addHttpRequest(num);
            num++;

            String path = request.path();

            String baseRequest = request.toString();

            if(checkBoxFullPath.isSelected()) {

                int start = baseRequest.indexOf(path) + 1;
                int end = start+path.length()-1;

                String original = removeMakers(baseRequest);
                positions.put(find, new Position(start, end));
                renderRequestForAll(find, original, request);
                fullSelected.put(find, true);
                requestEditor.uiComponent().requestFocusInWindow();
            }else{
                fullSelected.put(find, false);
                checkBoxFullPath.setSelected(false);
            }

        });

        return List.of(item);
    }

    //add Request one by one to display
    private void addHttpRequest(int id) {
        JButton payloadButton = new JButton(""+id);
        payloadButton.setMaximumSize(new Dimension(100, 30));
        payloadButton.setFocusPainted(false);
        payloadButton.setOpaque(true);
        payloadButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        buttons.put(id, payloadButton);

        //add button to each request
        payloadButton.addActionListener(e -> {

            find = id;
            activeId = find;
            refreshButtons();

            Boolean state = selected.get(find);
            checkBox.setSelected(state != null && state);


            Boolean fullState = fullSelected.get(find);
            checkBoxFullPath.setSelected(fullState != null && fullState);

            HttpRequest request = req.get(find);

            if(request == null) return;

            if (!positions.containsKey(find)) {
                requestEditor.setRequest(request);
                return;
            }

            String text = request.toString();

            StringBuilder sb = stringBuilder(text, find);

            String requestText = sb.toString();

            try {
                HttpService httpService = request.httpService();
                HttpRequest newRequest = HttpRequest.httpRequest(httpService, requestText);

                requestEditor.setRequest(newRequest);

            }catch (Exception er){
                StringWriter sw = new StringWriter();
                er.printStackTrace(new PrintWriter(sw));
                logger.logToError(sw.toString());
            }

        });
        leftPanel.add(payloadButton);
        leftPanel.revalidate();
        leftPanel.repaint();
    }

    //buttons are refreshed
    private void refreshButtons() {
        for(Map.Entry<Integer, JButton> button : buttons.entrySet()) {
            int id = button.getKey();
            activeButton(id, button.getValue());
        }
    }

    //set background when button is clicked
    private void activeButton(int id, JButton payloadButton) {
        if(activeId == id) {
            payloadButton.setBackground(Color.LIGHT_GRAY);
        }else{
            payloadButton.setBackground(UIManager.getColor("Button.background"));
        }
    }

    //unload
    @Override
    public void extensionUnloaded() {

        for (AttackSession session : sessions) {

            if (session == null) continue;

            session.pause = false;
            session.running.set(false);

            synchronized (session.lock) {
                session.lock.notifyAll();
            }

            if(session.frame != null) {
                SwingUtilities.invokeLater(session.frame::dispose);
            }

            if(session.filterFrame != null) {
                SwingUtilities.invokeLater(session.filterFrame::dispose);
            }

            if (session.scheduler != null) {
                session.scheduler.shutdownNow();
            }

            if (session.executor != null) {
                session.executor.shutdownNow();
            }
        }

    }

    //placeholder input field
    static class PlaceholderTextField extends JTextField {

        private final String placeholder;

        public PlaceholderTextField(String placeholder) {
            this.placeholder = placeholder;
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if(getText().isEmpty() && !isFocusOwner()) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setFont(new Font("Consales", Font.PLAIN, 14));
                g2.setColor(Color.GRAY);
                g2.drawString(placeholder, 10, 20);
            }
        }
    }

}
