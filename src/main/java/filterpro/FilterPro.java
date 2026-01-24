package filterpro;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.Timer;
import java.util.TimerTask;

public class FilterPro implements BurpExtension, ContextMenuItemsProvider {
    private MontoyaApi api;
    private Logging logging;
    private RuleManagerPanel ruleManagerPanel;
    private List<FilterRule> ruleList;
    private Timer autoSaveTimer;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.ruleList = new ArrayList<>();
        this.ruleManagerPanel = new RuleManagerPanel(api, ruleList);

        // 设置扩展名称
        api.extension().setName("FilterPro");

        // 注册规则管理面板为Burp的一个标签页
        api.userInterface().registerSuiteTab("FilterPro", ruleManagerPanel);

        // 注册上下文菜单项
        api.userInterface().registerContextMenuItemsProvider(this);

        // 启动自动保存定时器
        startAutoSaveTimer();

        logging.logToOutput("FilterPro 插件加载成功！");
    }

    /**
     * 启动自动保存定时器，每300秒自动保存一次配置
     */
    private void startAutoSaveTimer() {
        autoSaveTimer = new Timer(true); // 设置为守护线程
        long interval = 300 * 1000; // 300秒转换为毫秒

        autoSaveTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                try {
                    ruleManagerPanel.autoSaveConfig();
                } catch (Exception e) {
                    logging.logToError("自动保存配置时出错: " + e.getMessage());
                }
            }
        }, interval, interval); // 延迟interval后执行，然后每interval重复执行

        logging.logToOutput("自动保存定时器已启动，间隔: " + interval + " 毫秒");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        List<HttpRequestResponse> selectedMessages = new ArrayList<>();

        if (!event.selectedRequestResponses().isEmpty()) {
            selectedMessages = event.selectedRequestResponses();
        } else if (event.messageEditorRequestResponse().isPresent()) {
            selectedMessages.add(event.messageEditorRequestResponse().get().requestResponse());
        }

        if (!selectedMessages.isEmpty()) {
            HttpRequestResponse requestResponse = selectedMessages.get(0);
            JMenu filterProMenu = new JMenu("FilterPro");

            JMenuItem filterApiArgMenu = new JMenuItem("Filter_Api");
            JMenuItem filterHostMenu = new JMenuItem("Filter_Host");
            JMenuItem filterMethodMenu = new JMenuItem("Filter_Method");
            JMenuItem filterCustomMenu = new JMenuItem("Filter_Custom");

            final HttpRequestResponse finalRequestResponse = requestResponse;
            filterMethodMenu.addActionListener(e -> handleFilterMethod(finalRequestResponse));
            filterHostMenu.addActionListener(e -> handleFilterHost(finalRequestResponse));
            filterApiArgMenu.addActionListener(e -> handleFilterApiArg(finalRequestResponse));
            filterCustomMenu.addActionListener(e -> handleCustomRule(finalRequestResponse));

            filterProMenu.add(filterApiArgMenu);
            filterProMenu.add(filterCustomMenu);
            filterProMenu.add(filterHostMenu);
            filterProMenu.add(filterMethodMenu);

            menuItems.add(filterProMenu);
        }

        return menuItems;
    }

    private void handleFilterMethod(HttpRequestResponse requestResponse) {
        try {
            String method = requestResponse.request().method();
            String escapedMethod = escapeRegex(method);
            String rule = escapedMethod + " /";
//            默认添加到Default
            ruleList.add(new FilterRule(rule, "Method Filter", true, "", "Default group"));
            ruleManagerPanel.refreshTable();
            logging.logToOutput("添加方法过滤规则: " + rule);
        } catch (Exception e) {
            logging.logToError("处理请求方法时出错: " + e.getMessage());
        }
    }

    private void handleFilterHost(HttpRequestResponse requestResponse) {
        try {
            String host = requestResponse.request().httpService().host();
            String rule = escapeRegex("Host: "+ host);
            if (rule != null && !rule.trim().isEmpty()) {
//                默认添加到Default
                ruleList.add(new FilterRule(rule, "Host Filter", true, "", "Default group"));
                ruleManagerPanel.refreshTable();
                logging.logToOutput("添加主机过滤规则: " + rule);
            }
        } catch (Exception e) {
            logging.logToError("处理主机过滤时出错: " + e.getMessage());
        }
    }

    private void handleFilterApiArg(HttpRequestResponse requestResponse) {
        try {
            String path = requestResponse.request().path();
            String rule = escapeRegex(path);
            if (rule != null && !rule.trim().isEmpty()) {
//                默认添加到Default
                ruleList.add(new FilterRule(rule, "API Filter", true, "", "Default group"));
                ruleManagerPanel.refreshTable();
                logging.logToOutput("添加API参数过滤规则: " + rule);
            }
        } catch (Exception e) {
            logging.logToError("处理API参数过滤时出错: " + e.getMessage());
        }
    }

    private void handleCustomRule(HttpRequestResponse requestResponse) {
        try {
            String userInput = JOptionPane.showInputDialog(
                    null,
                    "请输入自定义规则内容:",
                    "自定义规则输入",
                    JOptionPane.QUESTION_MESSAGE
            );

            if (userInput == null || userInput.trim().isEmpty()) {
                logging.logToOutput("用户取消输入或输入为空");
                return;
            }

            String escapedRule = escapeRegex(userInput.trim());
//            规则默认添加到Default组
            ruleList.add(new FilterRule(escapedRule, "Custom Rule", true, "", "Default group"));
            ruleManagerPanel.refreshTable();

        } catch (Exception e) {
            logging.logToError("处理自定义规则时出错: " + e.getMessage());
            JOptionPane.showMessageDialog(
                    null,
                    "添加自定义规则时出错: " + e.getMessage(),
                    "错误",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private String escapeRegex(String input) {
        if (input == null) return "";
        return input.replace(".", "\\.").replace("?", "\\?");
    }
}

class RuleManagerPanel extends JPanel {
    private MontoyaApi api;
    private Logging logging;
    private List<FilterRule> ruleList;
    private List<RuleGroup> groupList;
    private RuleGroup currentGroup;
    private JTable ruleTable;
    private JTable groupTable;
    private RuleTableModel tableModel;
    private GroupTableModel groupTableModel;
    private JButton deleteButton;
    private JButton generateButton;
    private JButton saveConfigButton;
    private JButton loadConfigButton;
    private JButton addGroupButton;
    private JButton deleteGroupButton;
    private JButton editGroupButton;
    private JButton moveToGroupButton;
    private JTextArea finalRuleArea;
    private JLabel filePathLabel;
    private JTextField searchField;
    private File configFile;
    private static final String DEFAULT_FILENAME = "Filter_Pro_Rule.txt";
    private long lastSaveTime;
    private int autoSaveCount;

    public RuleManagerPanel(MontoyaApi api, List<FilterRule> ruleList) {
        this.api = api;
        this.logging = api.logging();
        this.ruleList = ruleList;
        this.groupList = new ArrayList<>();
        this.autoSaveCount = 0;
        this.lastSaveTime = System.currentTimeMillis();

        // 初始化Default group
        initializeDefaultGroups();

        // 设置当前分组为Default group
        if (!groupList.isEmpty()) {
            currentGroup = groupList.get(0);
        }

        initializeConfigFile();
        initializeUI(); // 先初始化UI组件
        loadDefaultConfig(); // 然后加载配置
    }

    private void initializeDefaultGroups() {
        groupList.add(new RuleGroup("Default group", "Default group"));
        // 移除固定的测试分组，改为动态加载
    }

    private void initializeConfigFile() {
        String currentDir = System.getProperty("user.dir");
        configFile = new File(currentDir, DEFAULT_FILENAME);
        if (!configFile.exists()) {
            try {
                configFile.createNewFile();
                logging.logToOutput("创建默认配置文件: " + configFile.getAbsolutePath());
            } catch (IOException e) {
                logging.logToError("创建配置文件失败: " + e.getMessage());
            }
        }
    }

    private void loadDefaultConfig() {
        if (configFile.exists() && configFile.length() > 0) {
            try (BufferedReader reader = new BufferedReader(new FileReader(configFile))) {
                ruleList.clear();
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\\|", 5);
                    if (parts.length >= 3) {
                        String ruleContent = parts[0];
                        String ruleType = parts[1];
                        boolean enabled = Boolean.parseBoolean(parts[2]);
                        String remark = parts.length > 3 ? parts[3] : "";
                        String groupName = parts.length > 4 ? parts[4] : "Default group";

                        // 确保分组存在，如果不存在则动态创建
                        ensureGroupExists(groupName, "");

                        ruleList.add(new FilterRule(ruleContent, ruleType, enabled, remark, groupName));
                    }
                }
                logging.logToOutput("从默认配置文件加载规则: " + ruleList.size() + " 条");

                // 现在groupTableModel已经初始化，可以安全调用
                if (groupTableModel != null) {
                    groupTableModel.fireTableDataChanged();
                }
                refreshTable();
            } catch (IOException e) {
                logging.logToError("加载默认配置文件失败: " + e.getMessage());
            }
        }
    }

    private void initializeUI() {
        setLayout(new BorderLayout());

        // 创建顶部面板：文件路径和搜索框
        JPanel topPanel = new JPanel(new BorderLayout());
        filePathLabel = new JLabel("规则文件: " + configFile.getAbsolutePath() + " | 自动保存: 每300秒 | 已保存: " + autoSaveCount + " 次");
        filePathLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // 搜索面板
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        searchPanel.add(new JLabel("搜索: "));
        searchField = new JTextField(20);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { performSearch(); }
            public void removeUpdate(DocumentEvent e) { performSearch(); }
            public void insertUpdate(DocumentEvent e) { performSearch(); }
        });
        searchPanel.add(searchField);

        topPanel.add(filePathLabel, BorderLayout.WEST);
        topPanel.add(searchPanel, BorderLayout.EAST);

        // 创建主分割面板：左侧分组管理，右侧规则管理
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplitPane.setDividerLocation(300);

        // 左侧分组面板
        JPanel groupPanel = createGroupPanel();
        // 右侧规则面板
        JPanel rulePanel = createRulePanel();

        mainSplitPane.setLeftComponent(groupPanel);
        mainSplitPane.setRightComponent(rulePanel);

        add(topPanel, BorderLayout.NORTH);
        add(mainSplitPane, BorderLayout.CENTER);
    }

    private JPanel createGroupPanel() {
        JPanel groupPanel = new JPanel(new BorderLayout());

        // 分组表格
        groupTableModel = new GroupTableModel(groupList);
        groupTable = new JTable(groupTableModel);
        groupTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        groupTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = groupTable.getSelectedRow();
                if (selectedRow >= 0) {
                    currentGroup = groupList.get(selectedRow);
                    refreshTable();
                }
            }
        });

        JScrollPane groupScrollPane = new JScrollPane(groupTable);

        // 分组操作按钮
        JPanel groupButtonPanel = new JPanel(new GridLayout(2, 4, 5, 5));
        addGroupButton = new JButton("添加分组");
        moveToGroupButton = new JButton("移动规则");
        deleteGroupButton = new JButton("删除分组");
        editGroupButton = new JButton("编辑分组");


        addGroupButton.addActionListener(e -> addGroup());
        deleteGroupButton.addActionListener(e -> deleteGroup());
        editGroupButton.addActionListener(e -> editGroup());
        moveToGroupButton.addActionListener(e -> moveRulesToGroup());

        groupButtonPanel.add(addGroupButton);
        groupButtonPanel.add(deleteGroupButton);
        groupButtonPanel.add(editGroupButton);
        groupButtonPanel.add(moveToGroupButton);

//        groupPanel.add(new JLabel("规则分组"), BorderLayout.NORTH);
        groupPanel.add(groupScrollPane, BorderLayout.CENTER);
        groupPanel.add(groupButtonPanel, BorderLayout.SOUTH);

        return groupPanel;
    }

    private JPanel createRulePanel() {
        JPanel rulePanel = new JPanel(new BorderLayout());

        // 规则表格
        tableModel = new RuleTableModel(getCurrentGroupRules());
        ruleTable = new JTable(tableModel);
        ruleTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane tableScrollPane = new JScrollPane(ruleTable);

        // 规则操作按钮
        JPanel ruleButtonPanel = new JPanel(new FlowLayout());
        deleteButton = new JButton("删除选中规则");
        generateButton = new JButton("生成过滤规则");
        saveConfigButton = new JButton("保存配置");
        loadConfigButton = new JButton("导入配置");

        deleteButton.addActionListener(e -> deleteSelectedRules());
        generateButton.addActionListener(e -> generateFinalRule());
        saveConfigButton.addActionListener(e -> saveConfig());
        loadConfigButton.addActionListener(e -> loadConfig());

        ruleButtonPanel.add(deleteButton);
        ruleButtonPanel.add(generateButton);
        ruleButtonPanel.add(saveConfigButton);
        ruleButtonPanel.add(loadConfigButton);

        // 规则显示区域
        finalRuleArea = new JTextArea(5, 50);
        finalRuleArea.setEditable(true);
        JScrollPane ruleScrollPane = new JScrollPane(finalRuleArea);
        JPanel ruleDisplayPanel = new JPanel(new BorderLayout());
        ruleDisplayPanel.add(new JLabel("过滤规则:复制到过滤器进行过滤或匹配"), BorderLayout.NORTH);
        ruleDisplayPanel.add(ruleScrollPane, BorderLayout.CENTER);

        // 垂直分割面板
        JSplitPane verticalSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, ruleDisplayPanel);
        verticalSplitPane.setDividerLocation(0.9); // 设置分割条在 80% 的位置（上方占 4/5，下方占 1/5）

        rulePanel.add(verticalSplitPane, BorderLayout.CENTER);
        rulePanel.add(ruleButtonPanel, BorderLayout.SOUTH);

        return rulePanel;
    }

    /**
     * 自动保存配置（静默保存，不显示提示框）
     */
    public void autoSaveConfig() {
        if (ruleList.isEmpty()) {
            return; // 如果没有规则，不执行保存
        }

        try (PrintWriter writer = new PrintWriter(new FileWriter(configFile))) {
            for (FilterRule rule : ruleList) {
                writer.println(rule.getRuleContent() + "|" +
                        rule.getRuleType() + "|" +
                        rule.isEnabled() + "|" +
                        (rule.getRemark() != null ? rule.getRemark() : "") + "|" +
                        rule.getGroupName());
            }
            autoSaveCount++;
            long currentTime = System.currentTimeMillis();
            long timeSinceLastSave = (currentTime - lastSaveTime) / 1000;
            lastSaveTime = currentTime;

            // 更新文件路径标签显示自动保存信息
            if (filePathLabel != null) {
                filePathLabel.setText("规则文件: " + configFile.getAbsolutePath() +
                        " | 自动保存: 每300秒 | 已保存: " + autoSaveCount + " 次 | 距上次: " + timeSinceLastSave + "秒前");
            }

            logging.logToOutput("自动保存配置成功！规则数量: " + ruleList.size() + " 条, 保存次数: " + autoSaveCount);
        } catch (IOException e) {
            logging.logToError("自动保存配置时出错: " + e.getMessage());
        }
    }

    private List<FilterRule> getCurrentGroupRules() {
        List<FilterRule> currentRules = new ArrayList<>();
        if (currentGroup != null) {
            for (FilterRule rule : ruleList) {
                if (rule.getGroupName().equals(currentGroup.getGroupName())) {
                    currentRules.add(rule);
                }
            }
        }
        return currentRules;
    }

    /**
     * 获取当前显示的规则列表（搜索时返回搜索结果，否则返回当前分组规则）
     */
    private List<FilterRule> getDisplayedRules() {
        String searchText = searchField.getText().toLowerCase().trim();
        if (!searchText.isEmpty()) {
            // 返回搜索结果的规则列表
            List<FilterRule> searchResults = new ArrayList<>();
            for (FilterRule rule : ruleList) {
                if (rule.getRuleContent().toLowerCase().contains(searchText) ||
                        rule.getRuleType().toLowerCase().contains(searchText) ||
                        rule.getRemark().toLowerCase().contains(searchText) ||
                        rule.getGroupName().toLowerCase().contains(searchText)) {
                    searchResults.add(rule);
                }
            }
            return searchResults;
        } else {
            // 返回当前分组的规则列表
            return getCurrentGroupRules();
        }
    }

    private void performSearch() {
        String searchText = searchField.getText().toLowerCase().trim();
        if (searchText.isEmpty()) {
            // 搜索框为空时，显示当前分组规则
            tableModel.setRuleList(getCurrentGroupRules());
        } else {
            // 执行搜索，显示全局搜索结果
            List<FilterRule> searchResults = new ArrayList<>();
            for (FilterRule rule : ruleList) {
                if (rule.getRuleContent().toLowerCase().contains(searchText) ||
                        rule.getRuleType().toLowerCase().contains(searchText) ||
                        rule.getRemark().toLowerCase().contains(searchText) ||
                        rule.getGroupName().toLowerCase().contains(searchText)) {
                    searchResults.add(rule);
                }
            }
            tableModel.setRuleList(searchResults);
        }
        tableModel.fireTableDataChanged();
    }

    // 分组操作方法
    private void addGroup() {
        String groupName = JOptionPane.showInputDialog(this, "请输入分组名称:", "添加分组", JOptionPane.QUESTION_MESSAGE);
        if (groupName != null && !groupName.trim().isEmpty()) {
            String remark ="" ;
            groupList.add(new RuleGroup(groupName.trim(), remark));
            groupTableModel.fireTableDataChanged();
        }
    }

    private void deleteGroup() {
        int selectedRow = groupTable.getSelectedRow();
        if (selectedRow >= 0) {
            RuleGroup groupToDelete = groupList.get(selectedRow);
            if (groupToDelete.getGroupName().equals("Default group")) {
                JOptionPane.showMessageDialog(this, "不能删除Default group！");
                return;
            }

            int result = JOptionPane.showConfirmDialog(this,
                    "确定要删除分组 '" + groupToDelete.getGroupName() + "' 及其所有规则吗？",
                    "确认删除", JOptionPane.YES_NO_OPTION);

            if (result == JOptionPane.YES_OPTION) {
                // 将属于该分组的规则移动到Default group
                for (FilterRule rule : ruleList) {
                    if (rule.getGroupName().equals(groupToDelete.getGroupName())) {
                        rule.setGroupName("Default group");
                    }
                }
                groupList.remove(selectedRow);
                groupTableModel.fireTableDataChanged();
                refreshTable();
            }
        } else {
            JOptionPane.showMessageDialog(this, "请先选择要删除的分组");
        }
    }

    private void editGroup() {
        int selectedRow = groupTable.getSelectedRow();
        if (selectedRow >= 0) {
            RuleGroup groupToEdit = groupList.get(selectedRow);
            String newName = JOptionPane.showInputDialog(this, "修改分组名称:", groupToEdit.getGroupName());
            if (newName != null && !newName.trim().isEmpty()) {
                String oldName = groupToEdit.getGroupName();
                groupToEdit.setGroupName(newName.trim());

                // 更新规则中的分组名称
                for (FilterRule rule : ruleList) {
                    if (rule.getGroupName().equals(oldName)) {
                        rule.setGroupName(newName.trim());
                    }
                }

                groupTableModel.fireTableDataChanged();
                refreshTable();
            }

            String newRemark = JOptionPane.showInputDialog(this, "修改分组备注:", groupToEdit.getRemark());
            if (newRemark != null) {
                groupToEdit.setRemark(newRemark);
                groupTableModel.fireTableDataChanged();
            }
        } else {
            JOptionPane.showMessageDialog(this, "请先选择要编辑的分组");
        }
    }

    private void moveRulesToGroup() {
        int[] selectedRuleRows = ruleTable.getSelectedRows();
        if (selectedRuleRows.length == 0) {
            JOptionPane.showMessageDialog(this, "请先选择要移动的规则");
            return;
        }

        // 选择目标分组
        String[] groupNames = groupList.stream().map(RuleGroup::getGroupName).toArray(String[]::new);
        String targetGroupName = (String) JOptionPane.showInputDialog(this,
                "选择目标分组:", "移动规则", JOptionPane.QUESTION_MESSAGE, null, groupNames, groupNames[0]);

        if (targetGroupName != null) {
            List<FilterRule> currentRules = getCurrentGroupRules();
            for (int i = selectedRuleRows.length - 1; i >= 0; i--) {
                int modelRow = ruleTable.convertRowIndexToModel(selectedRuleRows[i]);
                if (modelRow >= 0 && modelRow < currentRules.size()) {
                    FilterRule rule = currentRules.get(modelRow);  // 使用已获取的列表
                    rule.setGroupName(targetGroupName);
                }
            }
            refreshTable();
            JOptionPane.showMessageDialog(this, "已移动 " + selectedRuleRows.length + " 条规则到分组: " + targetGroupName);
        }
    }

    public void refreshTable() {
        tableModel.setRuleList(getCurrentGroupRules());
        tableModel.fireTableDataChanged();
    }

    private void deleteSelectedRules() {
        int[] selectedRows = ruleTable.getSelectedRows();
        if (selectedRows.length > 0) {
            List<FilterRule> currentRules = getCurrentGroupRules();
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                int modelRow = ruleTable.convertRowIndexToModel(selectedRows[i]);
                if (modelRow >= 0 && modelRow < currentRules.size()) {
                    FilterRule ruleToRemove = currentRules.get(modelRow);
                    ruleList.remove(ruleToRemove);
                }
            }
            refreshTable();
            JOptionPane.showMessageDialog(this, "已删除 " + selectedRows.length + " 条规则");
        } else {
            JOptionPane.showMessageDialog(this, "请先选择要删除的规则");
        }
    }

    /**
     * 生成最终规则 - 基于当前显示内容（搜索结果显示搜索结果，否则显示分组规则）
     */
    private void generateFinalRule() {
        List<FilterRule> displayedRules = getDisplayedRules();
        StringBuilder finalRule = new StringBuilder();

        for (FilterRule rule : displayedRules) {
            if (rule.isEnabled()) {
                finalRule.append(rule.getRuleContent()).append("|");
            }
        }

        if (finalRule.length() > 0) {
            finalRule.deleteCharAt(finalRule.length() - 1);
        }

        String ruleText = finalRule.toString();
        try {
            Pattern.compile(ruleText);
            finalRuleArea.setText(ruleText);
            copyToClipboard(ruleText);

            // 显示生成规则的来源信息
            String sourceInfo = searchField.getText().isEmpty() ?
                    "当前分组 '" + (currentGroup != null ? currentGroup.getGroupName() : "Default") + "'" :
                    "搜索结果（关键词: '" + searchField.getText() + "'）";

            logging.logToOutput("基于" + sourceInfo + "生成规则: " + ruleText);
            JOptionPane.showMessageDialog(this,
                    "规则已生成并复制到剪贴板！\n生成来源: " + sourceInfo +
                            "\n规则数量: " + displayedRules.size() + " 条");
        } catch (PatternSyntaxException e) {
            logging.logToError("生成的正则表达式无效: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "生成的正则表达式无效: " + e.getMessage());
        }
    }

    private void copyToClipboard(String text) {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            StringSelection stringSelection = new StringSelection(text);
            clipboard.setContents(stringSelection, null);
        } catch (Exception e) {
            logging.logToError("复制到剪贴板失败: " + e.getMessage());
        }
    }

    private void saveConfig() {
        try (PrintWriter writer = new PrintWriter(new FileWriter(configFile))) {
            for (FilterRule rule : ruleList) {
                writer.println(rule.getRuleContent() + "|" +
                        rule.getRuleType() + "|" +
                        rule.isEnabled() + "|" +
                        (rule.getRemark() != null ? rule.getRemark() : "") + "|" +
                        rule.getGroupName());
            }
            JOptionPane.showMessageDialog(this, "配置保存成功！\n文件路径: " + configFile.getAbsolutePath());
            filePathLabel.setText("规则文件: " + configFile.getAbsolutePath() + " | 自动保存: 每300秒 | 已保存: " + autoSaveCount + " 次");
        } catch (IOException e) {
            logging.logToError("保存配置时出错: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "保存配置时出错: " + e.getMessage());
        }
    }

    private void loadConfig() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入配置");
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.dir")));

        int userSelection = fileChooser.showOpenDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToOpen = fileChooser.getSelectedFile();
            try (BufferedReader reader = new BufferedReader(new FileReader(fileToOpen))) {
                ruleList.clear();
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\\|", 5);
                    if (parts.length >= 3) {
                        String ruleContent = parts[0];
                        String ruleType = parts[1];
                        boolean enabled = Boolean.parseBoolean(parts[2]);
                        String remark = parts.length > 3 ? parts[3] : "";
                        String groupName = parts.length > 4 ? parts[4] : "默认分组";

                        // 确保分组存在，如果不存在则动态创建
                        ensureGroupExists(groupName, "从文件加载");

                        ruleList.add(new FilterRule(ruleContent, ruleType, enabled, remark, groupName));
                    }
                }
                // 刷新分组表格显示
                groupTableModel.fireTableDataChanged();
                refreshTable();
                JOptionPane.showMessageDialog(this, "配置导入成功！");
            } catch (IOException e) {
                logging.logToError("导入配置时出错: " + e.getMessage());
                JOptionPane.showMessageDialog(this, "导入配置时出错: " + e.getMessage());
            }
        }
    }

    /**
     * 确保分组存在，如果不存在则创建
     */
    private void ensureGroupExists(String groupName, String defaultRemark) {
        if (groupName == null || groupName.trim().isEmpty()) {
//            没有组默认创建Default
            groupName = "Default group";
        }

        for (RuleGroup group : groupList) {
            if (group.getGroupName().equals(groupName)) {
                return; // 分组已存在
            }
        }

        // 分组不存在，创建新分组
        groupList.add(new RuleGroup(groupName, defaultRemark.isEmpty() ? "" : defaultRemark));
//        关闭动态加载的日志
//        logging.logToOutput("动态创建分组: " + groupName);
    }
}

class RuleTableModel extends AbstractTableModel {
    private List<FilterRule> ruleList;
    private final String[] columnNames = {"启用", "规则内容", "规则类型", "备注", "组名"};

    public RuleTableModel(List<FilterRule> ruleList) {
        this.ruleList = ruleList;
    }

    public void setRuleList(List<FilterRule> ruleList) {
        this.ruleList = ruleList;
    }

    @Override
    public int getRowCount() {
        return ruleList.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return true;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        FilterRule rule = ruleList.get(rowIndex);
        switch (columnIndex) {
            case 0: return rule.isEnabled();
            case 1: return rule.getRuleContent();
            case 2: return rule.getRuleType();
            case 3: return rule.getRemark();
            case 4: return rule.getGroupName();
            default: return null;
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        FilterRule rule = ruleList.get(rowIndex);
        switch (columnIndex) {
            case 0: rule.setEnabled((Boolean) aValue); break;
            case 1: rule.setRuleContent((String) aValue); break;
            case 2: rule.setRuleType((String) aValue); break;
            case 3: rule.setRemark((String) aValue); break;
            case 4: rule.setGroupName((String) aValue); break;
        }
        fireTableCellUpdated(rowIndex, columnIndex);
    }
}

class GroupTableModel extends AbstractTableModel {
    private final List<RuleGroup> groupList;
    private final String[] columnNames = {"组名", "备注"};

    public GroupTableModel(List<RuleGroup> groupList) {
        this.groupList = groupList;
    }

    @Override
    public int getRowCount() {
        return groupList.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RuleGroup group = groupList.get(rowIndex);
        switch (columnIndex) {
            case 0: return group.getGroupName();
            case 1: return group.getRemark();
            default: return null;
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        RuleGroup group = groupList.get(rowIndex);
        switch (columnIndex) {
            case 0: group.setGroupName((String) aValue); break;
            case 1: group.setRemark((String) aValue); break;
        }
        fireTableCellUpdated(rowIndex, columnIndex);
    }
}

class FilterRule {
    private String ruleContent;
    private String ruleType;
    private boolean enabled;
    private String remark;
    private String groupName;

    public FilterRule(String ruleContent, String ruleType, boolean enabled, String remark, String groupName) {
        this.ruleContent = ruleContent;
        this.ruleType = ruleType;
        this.enabled = enabled;
        this.remark = remark;
        this.groupName = groupName;
    }

    public String getRuleContent() { return ruleContent; }
    public void setRuleContent(String ruleContent) { this.ruleContent = ruleContent; }
    public String getRuleType() { return ruleType; }
    public void setRuleType(String ruleType) { this.ruleType = ruleType; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getRemark() { return remark; }
    public void setRemark(String remark) { this.remark = remark; }
    public String getGroupName() { return groupName; }
    public void setGroupName(String groupName) { this.groupName = groupName; }
}

class RuleGroup {
    private String groupName;
    private String remark;

    public RuleGroup(String groupName, String remark) {
        this.groupName = groupName;
        this.remark = remark;
    }

    public String getGroupName() { return groupName; }
    public void setGroupName(String groupName) { this.groupName = groupName; }
    public String getRemark() { return remark; }
    public void setRemark(String remark) { this.remark = remark; }
}