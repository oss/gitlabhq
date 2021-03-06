class KeyObserver < ActiveRecord::Observer
  include Gitolited

  def after_save(key)
    GitoliteWorker.perform_async(
      :add_key,
      key.shell_id,
      key.key
    )
  end

  def after_destroy(key)
    GitoliteWorker.perform_async(
      :remove_key,
      key.shell_id,
      key.key,
    )
  end
end
