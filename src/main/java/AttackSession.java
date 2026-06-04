import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

class AttackSession {

    int rate;

    AtomicInteger runNum = new AtomicInteger();

    AtomicInteger tasks = new AtomicInteger();

    AtomicBoolean running = new AtomicBoolean(false);

    boolean urlEncode;

    volatile boolean pause = false;

    ScheduledExecutorService scheduler;

    ExecutorService executor;

    String url_value;



    JFrame frame;

    JFrame filterFrame;

    DefaultTableModel tableModel;

    Map<Integer, Result> results = new ConcurrentHashMap<>();

    final Object lock = new Object();

    JCheckBox success;

    JCheckBox redirection;

    JCheckBox requestError;

    JCheckBox serverError;



}