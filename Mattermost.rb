require 'java'
#require 'pry'
#require 'pry-nav'
java_import 'burp.IBurpExtender'
java_import 'burp.IExtensionHelpers'

java_import 'javax.swing.JOptionPane'
java_import 'burp.ITab'
java_import 'javax.swing.JPanel'
class AbtractBrupExtensionUI < JPanel
  include ITab

  def initialize(extension)
    @extension = extension
    super()
    self.setLayout nil
  end

  def getUiComponent
    self
  end
end

java_import('java.awt.Insets')
class AbstractBurpUIElement
  def initialize(parent, obj, positionX, positionY, width, height)
    @swingElement =obj
    setPosition parent, positionX, positionY, width, height
    parent.add @swingElement
  end

  def method_missing(method, *args, &block)
    @swingElement.send(method, *args)
  end

  private
  def setPosition(parent, x,y,width,height)
    insets = parent.getInsets
    size = @swingElement.getPreferredSize()
    w = (width > size.width) ? width : size.width
    h = (height > size.height) ? height : size.height
    @swingElement.setBounds(x + insets.left, y + insets.top, w, h)
  end
end

java_import 'javax.swing.JLabel'
class BLabel < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, align= :left)
    case align
    when :left
      a = 2
    when :right
      a = 4
    when :center
      a = 0
    else
      a = 2 #align left
    end
    super parent, JLabel.new(caption, a),positionX, positionY, width, height
  end
end


java_import 'javax.swing.JButton'
class BButton < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, &onClick)
    super parent, JButton.new(caption), positionX, positionY, width, height
    @swingElement.add_action_listener onClick
  end
end

java_import 'javax.swing.JSeparator'
class BHorizSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width)
    super parent, JSeparator.new(0), positionX, positionY, width, 1
  end
end

class BVertSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width)
    super parent, JSeparator.new(0), positionX, positionY, width, 1
  end
end

java_import 'javax.swing.JCheckBox'
class BCheckBox < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JCheckBox.new(caption), positionX, positionY, width, height
  end
end

java_import 'javax.swing.JTextField'
class BTextField < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JTextField.new(caption), positionX, positionY, width, height
  end
end

java_import 'javax.swing.JPasswordField'
class BPasswordField < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JPasswordField.new(caption), positionX, positionY, width, height
    @swingElement.setEchoChar('*')
  end

  def getText
    @swingElement.getPassword.to_a.map{|x| x.chr}.join
  end
end

java_import 'javax.swing.JComboBox'
class BComboBox < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height)
    super parent, JComboBox.new, positionX, positionY, width, height
  end
end

java_import 'javax.swing.JTextArea'
java_import 'javax.swing.JScrollPane'
class BTextArea < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height)
    @textArea = JTextArea.new
    super parent, JScrollPane.new(@textArea), positionX, positionY, width, height
  end

  def setText(text)
    @textArea.setText text
  end

  def getText
    @textArea.getText
  end
end
#########################################################################################
#Begin Burp Extension
#########################################################################################

require 'json'
require 'time'
class MatterMostClient
 CODE_BLOCK_MAX_LEN = 2500 #Split size for code posts
 attr_reader :server
 attr_accessor :login_id
 attr_accessor :password
 attr_reader :token
 attr_reader :lasterror

 def initialize(burpCallbacks)
   setuphttp
   @helpers = burpCallbacks.getHelpers
   @callbacks = burpCallbacks
   @server = ''
   @login_id = ''

   t =  @callbacks.loadExtensionSetting('MM_server')
   self.server = t if t
   t = @callbacks.loadExtensionSetting('MM_login_id')
   @login_id = t if t

   @teams = Hash.new
   @channels = Hash.new
 end

 def method_missing(method, *args, &block)
   if @helpers.respond_to? method
     @helpers.send(method, *args, &block)
   elsif @callbacks.respond_to? method
     @callbacks.send(method, *args, &block)
   else
     raise NoMethodError, "undefined method `#{method}` for #{self.class.name}"
   end
 end

 def token=(v)
   @token = v.to_s
 end

 def server=(host)
   @server = host
   @httpHeaders['orign'] = "https://#{host}"
   @httpService = buildHttpService host, 443, true
 end

 def authenticated?
   return true if @user_id
 end

 def authenticate
   message = Hash.new
   message['device_id'] = ''
   message['login_id'] = @login_id
   message['password'] = @password
   message['token'] = @token
   rsp = apireq '/api/v4/users/login', message
   raise RuntimeError, rsp['message'] if rsp['id'].include? 'app_error'
   @user_id = rsp['id']
   get_teams #Do this once on login
   get_channels #get some initial info
   @callbacks.saveExtensionSetting('MM_login_id', @login_id) #save the user on a successful login
   @callbacks.saveExtensionSetting('MM_server', @server) #save the server on a successful login
   true
 rescue => e
   @lasterror = e.message
   false
 end

 def logout
   rsp = apireq '/api/v4/users/logout', {}
   raise RuntimeError, rsp['message'] unless rsp['status'] == 'OK'
   true
 rescue => e
   @lasterror = e.message
   false
 ensure
   @user_id = nil
   @httpCookies = Hash.new
 end

  def channels(update=false)
    get_channels if update
    @channels.keys
  rescue => e
    @lasterror = e.message
    return []
  end

 def post_burp_response(channel, obj)
   bytesToString(obj.getResponse).to_s.scan(/.{1,#{CODE_BLOCK_MAX_LEN}}/m) {|str| post_as_code(channel, str)}
 end

 def post_burp_request(channel, obj)
   bytesToString(obj.getRequest).to_s.scan(/.{1,#{CODE_BLOCK_MAX_LEN}}/m) {|str| post_as_code(channel, str)}
 end

 def post_as_code(channel, text)
   post channel, "```\n#{text}\n```"
 end

 def post(channel, text)
   message = Hash.new
   message['file_ids'] = []
   message['message'] = text
   message['channel_id'] = @channels[channel]
   raise RuntimeError 'Unknown Channel for message post' unless message['channel_id']
   message['pending_post_id'] = id_gen
   message['user_id'] = @user_id
   message['create_at'] = 0
   message['update_at'] = utime
   rsp = apireq '/api/v4/posts', message
   true
 rescue => e
   @lasterror = e.message
   false
 end

  private

 def setuphttp
   @httpService = nil
   @httpCookies = Hash.new
   @httpHeaders = {
       'User-Agent' => 'Mozilla/5.0 (Burpsuite; Intel Java; rv:64.0) Gecko/20100101 Firefox/64.0',
       'x-requested-with' => 'XMLHttpRequest',
       'Accept' => '*/*',
       'Accept-Language' => 'en',
       'x-csrf-token' => '',
       'content-type' => 'text/plain;charset=UTF-8',
       'orign' => ''
   }
 end

 def id_gen
   id = Array.new(27)
   id.map! {|x| x = (((rand * 100).to_i % 25) + 97).chr}
   id.join ''
 end

 def utime
   Time.now.to_i * 1000
 end

 def get_channels(type_filter=['O','P'])
   raise RuntimeError, 'Must Authenticate First' unless authenticated?
   @channels = Hash.new
   @teams.each do |teamname, teamId|
     rsp = apireq("/api/v4/users/me/teams/#{teamId}/channels")
     rsp.each do |channel|
       @channels["#{teamname}_#{channel['display_name']}"] = channel['id'] if type_filter.include? channel['type']
     end
   end
   true
 end

  def get_teams
    rsp = apireq('/api/v4/users/me/teams')
    rsp.each do |team|
      @teams[team['display_name']] = team['id']
    end
  end

  def apireq(path, body=nil)
    raise RuntimeError, 'No configuration provided' unless @httpService

    headers = @httpHeaders.map {|k,v| "#{k}: #{v}"}
    if @httpCookies.count > 0
      headers << "Cookie: #{@httpCookies.map {|k,v| "#{k}=#{v}"}.join('; ')}"
    end
    headers.unshift "Host: #{@server}"
    unless body
      headers.unshift "GET #{path} HTTP/1.1"
      message = buildHttpMessage(headers, nil)
    else
      headers.unshift "POST #{path} HTTP/1.1"
      message = buildHttpMessage(headers, stringToBytes(body.to_json))
    end
    response = makeHttpRequest(@httpService, message)
    info = analyzeResponse(response.getResponse)
    raise RuntimeError, "Server Responded with HTTP Error" if info.getStatusCode >= 400
    raise RuntimeError, "Server Did not reply with JSON" unless info.getStatedMimeType == 'JSON'
    updateCookieJar(info)
    JSON.parse bytesToString(response.getResponse[(info.getBodyOffset)..-1])
  end

  def updateCookieJar(requestInfo)
    requestInfo.getCookies.each do |cookie|
      @httpCookies[cookie.name] = cookie.value
      @httpHeaders['x-csrf-token'] = cookie.value if cookie.name == 'MMCSRF' #Suspect but seems to work.
    end
  end

end

java_import 'javax.swing.JMenuItem'
class BMenuItem < JMenuItem
  def initialize(text, &onClick)
    super(text)
    self.add_action_listener onClick
  end
end

class MatterMostUI < AbtractBrupExtensionUI
  def extensionName
    'Mattermost'
  end

  alias_method :getTabCaption, :extensionName

  def client
    @extension
  end

  def buildUI
    BLabel.new self, 2,2,100,14,'Server:'
    @txt_server = BTextField.new self,100,2,250,14, client.server
    BLabel.new self, 2,25, 100, 14, 'Login:'
    @txt_login_id = BTextField.new self,100,25,250,14, client.login_id
    BLabel.new self, 2,50, 100, 14, 'Password:'
    @txt_password = BPasswordField.new self,100,50,250,14, ''
    BLabel.new self, 2,75, 100, 14, 'MFA Token:'
    @txt_token = BTextField.new self,100,75,250,14, ''
    BHorizSeparator.new self, 2, 150, 550
    BLabel.new self, 2,155, 50, 14, 'Status:'
    @txt_status = BLabel.new self, 50,155,250,14,'Not Ready'

    BButton.new self, 100, 125,60 ,14, 'Update Channels' do |evt|
      Thread.new do
        @txt_status.setText('Getting Latest Channels')
        JOptionPane.showMessageDialog(nil, client.lasterror) unless client.channels(true).length > 0
        @txt_status.setText('Ready')
      end
    end

    @btn_login = BButton.new self, 2, 125,60 ,14, 'Login ' do |evt|
      @btn_login.setEnabled(false)
      if client.authenticated?
        do_logout
      else
        do_login
      end
    end
  end

  def do_login
    @txt_status.setText('Login in progress...')
    client.server = @txt_server.getText
    client.login_id = @txt_login_id.getText
    client.password = @txt_password.getText
    client.token = @txt_token.getText
    Thread.new do
      JOptionPane.showMessageDialog(nil, client.lasterror) unless client.authenticate
      @txt_status.setText('Ready') if client.authenticated?
      @btn_login.setText('Logout')
      @btn_login.setEnabled(true)
    end
  end

  def do_logout
    @txt_status.setText('Logout in progress...')
    Thread.new do
      JOptionPane.showMessageDialog(nil, client.lasterror) unless client.logout
      @btn_login.setText('Login')
      @txt_status.setText('Ready')
      @btn_login.setEnabled(true)
    end
  end

  end

java_import 'burp.IContextMenuFactory'
class MatterMostContextMenuFactory
  include IContextMenuFactory

  CONTEXT_MESSAGE_EDITOR_REQUEST = 0
  CONTEXT_MESSAGE_EDITOR_RESPONSE = 1
  CONTEXT_MESSAGE_VIEWER_REQUEST = 2
  CONTEXT_MESSAGE_VIEWER_RESPONSE = 3

  attr_accessor :client

  def initialize(client)
    @client = client
  end

  def createMenuItems(invocation)
    return nil unless client.authenticated?
    return nil unless [CONTEXT_MESSAGE_EDITOR_REQUEST, CONTEXT_MESSAGE_EDITOR_RESPONSE, CONTEXT_MESSAGE_VIEWER_REQUEST, CONTEXT_MESSAGE_VIEWER_RESPONSE].include? invocation.getInvocationContext
    items = Array.new
    client.channels.each do |channel|
      items << BMenuItem.new("(Mattermost) Send to: #{channel}") {sendContent(channel, invocation)}
    end
    items
  end

  def sendContent(channel, invocation)
    case invocation.getInvocationContext
    when CONTEXT_MESSAGE_EDITOR_REQUEST
      Thread.new { client.post_burp_request(channel, (invocation.getSelectedMessages()[0]))}
    when CONTEXT_MESSAGE_VIEWER_REQUEST
      Thread.new { client.post_burp_request(channel, (invocation.getSelectedMessages()[0]))}
    when CONTEXT_MESSAGE_EDITOR_RESPONSE
      Thread.new { client.post_burp_response(channel, (invocation.getSelectedMessages()[0]))}
    when CONTEXT_MESSAGE_VIEWER_RESPONSE
      Thread.new { client.post_burp_response(channel, (invocation.getSelectedMessages()[0]))}
    end
  end
end

  class BurpExtender
    include IBurpExtender
    ExtensionName = 'Mattermost'

    def registerExtenderCallbacks(callbacks)
      callbacks.setExtensionName ExtensionName
      client = MatterMostClient.new callbacks
      ui = MatterMostUI.new(client)
      menu_factory = MatterMostContextMenuFactory.new(client)
      callbacks.addSuiteTab(ui)
      ui.buildUI
      callbacks.customizeUiComponent ui
      callbacks.registerContextMenuFactory menu_factory
    end

  end
